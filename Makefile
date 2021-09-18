COMMIT_HASH=$(shell git rev-parse --short HEAD || echo "GitNotFound")
BUILD_DATE=$(shell date '+%Y-%m-%d %H:%M:%S')

all: build

build: sqlpacket
sqlpacket:
	go build -ldflags "-X \"main.BuildVersion=${COMMIT_HASH}\" -X \"main.BuildDate=$(BUILD_DATE)\"" -o ./bin/sqlpacket main.go
clean:
	@rm -rf bin

test:
	go test ./go/... -race
