package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"os/signal"
	"pacptest/config"
	"strings"
	"syscall"
	"time"
)

var configFile *string = flag.String("config", "etc/config.yaml", "audit plugin config file")

var (
    snapshotLen  int32         = 65535
    promiscuous  bool          = true
    port         uint16        = 3306
    connTimeout  time.Duration = 2
    retryTime    time.Duration = 5 * time.Second
)

func connectServer(cfg *config.Config) (conn net.Conn, err error) {
	conn, err = net.DialTimeout("tcp", cfg.Addr,  connTimeout * time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tcp failed: %s", err)
	}
	return conn, nil
}

func sendPacket(cfg *config.Config, dev string) {
	fmt.Println("dev: ", dev)
	handle, err := pcap.OpenLive(dev, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal("open device", dev," failed: ", err)
	}
	defer handle.Close()

	filter := getFilter(port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("set bpf filter failed: ", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	conn, err := connectServer(cfg)
	if err != nil {
		log.Fatal("dial server failed: ", err)
	}
	defer conn.Close()

	for packet := range packetSource.Packets() {
		packetData := packet.Data()
		length := len(packetData) + 15 // 15 byte for timestamp binary marshal

		data := make([]byte, 4, length + 4)
		data[0] = byte(length)
		data[1] = byte(length >> 8)
		data[2] = byte(length >> 16)
		data[3] = byte(length >> 24)

		timeInfo,_ := packet.Metadata().Timestamp.MarshalBinary()
		data = append(data, timeInfo...)

		data = append(data, packetData...)

		if conn != nil {
			_, err := conn.Write(data)
			if err != nil {
				_ = conn.Close()
				// TODO: retry connect here
				conn, err = connectServer(cfg)
				if err != nil  {
					time.Sleep(retryTime)
				}
			}
		} else {
			conn, err = connectServer(cfg)
			if err != nil {
				time.Sleep(retryTime)
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

	devs := strings.Split(cfg.Dev, ",")

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
	filter := fmt.Sprintf("tcp and ((src port %v) or (dst port %v))",  port, port)
	return filter
}

