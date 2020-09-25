TAG ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)

LDFLAGS = -ldflags '-s -w -extldflags "-static"'

.PHONY: build
build:
	go build $(LDFLAGS) -o bin/host ./cmd/host
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/vm ./cmd/vm

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: crc
crc: build
	scp bin/vm crc:

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run

.PHONY: image
image:
	docker build -t quay.io/crcont/gvisor-tap-vsock:$(TAG) .

.PHONY: cross
cross:
	GOOS=windows go build $(LDFLAGS) -o bin/host-windows.exe ./cmd/host
	GOOS=darwin  go build $(LDFLAGS) -o bin/host-darwin ./cmd/host
	GOOS=linux   go build $(LDFLAGS) -o bin/host-linux ./cmd/host

.PHONY: test
test: build
	go test -v ./test