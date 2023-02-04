package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jixindatech/sqlpacket/config"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var configFile = flag.String("config", "etc/config.yaml", "audit plugin config file")

var (
	snapshotLen int32         = 65535
	connTimeout time.Duration = 2
	retryTime                 = 5 * time.Second
	retryCount  int32         = 5
)

func writeHeader(conn net.Conn) error {
	buff := bytes.NewBuffer([]byte{})
	_ = binary.Write(buff, binary.BigEndian, []byte{0x00, 0x00, 0x00, 0x04}) // length
	_ = binary.Write(buff, binary.BigEndian, int16(config.SQL_CLASS))        // type class
	_ = binary.Write(buff, binary.BigEndian, int16(config.SQL_TYPE_MYSQL))   // type
	_, err := conn.Write(buff.Bytes())
	return err
}

func connectServer(cfg *config.Config) (conn net.Conn, err error) {
	conn, err = net.DialTimeout("tcp", cfg.Server, connTimeout*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp failed: %s", err)
	}

	err = writeHeader(conn)

	return conn, err
}

func reConnectServer(cfg *config.Config) (net.Conn, error) {
	count := retryCount
	conn, err := connectServer(cfg)
	for {
		count--
		if err != nil {
			time.Sleep(retryTime)
		}

		if conn != nil {
			break
		}

		if count <= 0 {
			return nil, errors.New("reconnect server failed too many times")
		}

		conn, err = connectServer(cfg)
	}

	return conn, nil
}
func sendPacket(cfg *config.Config, dev string) {
	conn, err := connectServer(cfg)
	if err != nil {
		log.Fatal("dial server failed: ", err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Fatal("conn close failed:", err)
		}
	}(conn)

	handle, err := pcap.OpenLive(dev, snapshotLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("open device", dev, " failed: ", err)
	}
	defer handle.Close()

	filter := getFilter(cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("set bpf filter failed: ", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for packet := range packetSource.Packets() {
		packetData := packet.Data()
		length := len(packetData) + 15 // 15 byte for timestamp binary marshal

		data := make([]byte, 4, length+4)
		data[0] = byte(length)
		data[1] = byte(length >> 8)
		data[2] = byte(length >> 16)
		data[3] = byte(length >> 24)

		timeInfo, _ := packet.Metadata().Timestamp.MarshalBinary()
		data = append(data, timeInfo...)

		data = append(data, packetData...)

		if conn != nil {
			sendBytes, err := conn.Write(data)
			if err != nil {
				_ = conn.Close()
				// TODO: retry connect here
				conn, err = reConnectServer(cfg)
				if err != nil {
					log.Fatal(err)
				}
			}
			_, err = conn.Write(data[sendBytes:])
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// TODO: retry connect here
			conn, err = reConnectServer(cfg)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func main() {
	flag.Parse()

	if len(*configFile) == 0 {
		log.Fatal("must use a config file")
	}

	cfg, err := config.ParseConfigFile(*configFile)
	if err != nil {
		log.Fatal("parse config file failed:", err)
	}

	devs := strings.Split(cfg.Inf, ",")

	for _, dev := range devs {
		go sendPacket(cfg, dev)
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGPIPE,
	)

	for {
		sig := <-sc
		if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == syscall.SIGQUIT {
			break
		} else if sig == syscall.SIGPIPE {
			//IGNORE
		}
	}
}

func getFilter(port uint16) string {
	filter := fmt.Sprintf("tcp and ((src port %v) or (dst port %v))", port, port)
	return filter
}
