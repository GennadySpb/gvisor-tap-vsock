package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/transport"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	endpoint           string
	iface              string
	debug              bool
	retry              int
	changeDefaultRoute bool
)

func main() {
	flag.StringVar(&endpoint, "url", "vsock://2:1024/connect", "url where the tap send packets")
	flag.StringVar(&iface, "iface", "tap0", "tap interface name")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.IntVar(&retry, "retry", 0, "number of connection attempts")
	flag.BoolVar(&changeDefaultRoute, "change-default-route", true, "change the default route to use this interface")
	flag.Parse()

	for {
		if err := run(); err != nil {
			if retry > 0 {
				retry--
				log.Error(err)
			} else {
				log.Fatal(err)
			}
		}
		time.Sleep(time.Second)
	}
}

func run() error {
	conn, path, err := transport.Dial(endpoint)
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
	defer conn.Close()

	req, err := http.NewRequest("POST", path, nil)
	if err != nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}

	handshake, err := handshake(conn)
	if err != nil {
		return errors.Wrap(err, "cannot handshake")
	}

	tap, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return errors.Wrap(err, "cannot create tap device")
	}
	defer tap.Close()

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh, handshake.MTU)
	go rx(conn, tap, errCh, handshake.MTU)

	c := make(chan os.Signal)
	cleanup, err := linkUp(handshake)
	defer func() {
		signal.Stop(c)
		cleanup()
	}()
	if err != nil {
		return err
	}
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		os.Exit(0)
	}()
	return <-errCh
}

func handshake(conn net.Conn) (types.Handshake, error) {
	sizeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return types.Handshake{}, err
	}
	size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))
	b := make([]byte, size)
	if _, err := io.ReadFull(conn, b); err != nil {
		return types.Handshake{}, err
	}
	var handshake types.Handshake
	if err := json.Unmarshal(b, &handshake); err != nil {
		return types.Handshake{}, err
	}
	return handshake, nil
}

func rx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	log.Info("waiting for packets...")
	var frame ethernet.Frame
	for {
		frame.Resize(mtu)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read packet from tap")
			return
		}
		frame = frame[:n]

		if debug {
			packet := gopacket.NewPacket(frame, layers.LayerTypeIPv4, gopacket.Default)
			log.Info(packet.String())
		}

		pkt := make([]byte, header.EthernetMinimumSize)
		eth := header.Ethernet(pkt)
		eth.Encode(&header.EthernetFields{
			Type:    header.IPv4ProtocolNumber,
			SrcAddr: tcpip.LinkAddress("\x5A\x94\xEF\xE4\x0C\xDE"),
			DstAddr: tcpip.LinkAddress("\xd2\x34\xca\xbf\x78\x76"),
		})

		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, uint16(n+header.EthernetMinimumSize))

		if _, err := conn.Write(size); err != nil {
			errCh <- errors.Wrap(err, "cannot write size to socket")
			return
		}
		if _, err := conn.Write(pkt); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to socket")
			return
		}
		if _, err := conn.Write(frame); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to socket")
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	sizeBuf := make([]byte, 2)
	buf := make([]byte, mtu+header.EthernetMinimumSize)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read size from socket")
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("unexpected size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())

			if fmt.Sprintf("%v", packet.Layers()[1].LayerType()) == "ARP" {
				continue
			}
		}

		if _, err := tap.Write(buf[header.EthernetMinimumSize:size]); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}
	}
}

func linkUp(handshake types.Handshake) (func(), error) {
	return func() {

	}, nil
}
