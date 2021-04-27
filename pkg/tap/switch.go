package tap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualDevice interface {
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
	LinkAddress() tcpip.LinkAddress
	IP() string
}

type NetworkSwitch interface {
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
}

type Switch struct {
	Sent     uint64
	Received uint64

	debug               bool
	maxTransmissionUnit int

	nextConnID int
	conns      map[int]*VirtualMachine
	connLock   sync.Mutex

	cam     map[tcpip.LinkAddress]int
	camLock sync.RWMutex

	gateway VirtualDevice

	IPs *IPPool
}

func NewSwitch(debug bool, mtu int, ipPool *IPPool) *Switch {
	return &Switch{
		debug:               debug,
		maxTransmissionUnit: mtu,
		conns:               make(map[int]*VirtualMachine),
		cam:                 make(map[tcpip.LinkAddress]int),
		IPs:                 ipPool,
	}
}

func (e *Switch) CAM() map[string]int {
	e.camLock.RLock()
	defer e.camLock.RUnlock()
	ret := make(map[string]int)
	for address, port := range e.cam {
		ret[address.String()] = port
	}
	return ret
}

func (e *Switch) Connect(ep VirtualDevice) {
	e.gateway = ep
}

func (e *Switch) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if err := e.tx(remote, local, protocol, pkt); err != nil {
		log.Error(err)
	}
}

func (e *Switch) Accept(conn net.Conn) {
	log.Infof("new connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	id, failed := e.connect(conn)
	if failed {
		log.Error("connection failed")
		_ = conn.Close()
		return
	}

	defer func() {
		e.connLock.Lock()
		defer e.connLock.Unlock()
		e.disconnect(id, conn)
	}()
	if err := e.rx(id, conn); err != nil {
		log.Error(errors.Wrapf(err, "cannot receive packets from %s, disconnecting", conn.RemoteAddr().String()))
		return
	}
}

func (e *Switch) connect(conn net.Conn) (int, bool) {
	e.connLock.Lock()
	defer e.connLock.Unlock()

	id := e.nextConnID
	e.nextConnID++

	factory := &VirtualMachineFactory{
		MTU:       e.maxTransmissionUnit,
		GatewayIP: e.gateway.IP(),
		IPs:       e.IPs,
	}

	vm, err := factory.handshake(id, conn)
	if err != nil {
		log.Error(errors.Wrapf(err, "cannot handshake with %s", conn.RemoteAddr().String()))
		return 0, true
	}

	e.conns[id] = vm
	return id, false
}

func (e *Switch) tx(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) error {
	e.connLock.Lock()
	defer e.connLock.Unlock()

	if remote == header.EthernetBroadcastAddress {
		e.camLock.RLock()
		srcID, ok := e.cam[local]
		if !ok {
			srcID = -1
		}
		e.camLock.RUnlock()
		for id, vm := range e.conns {
			if id == srcID {
				continue
			}
			if err := vm.DeliverNetworkPacket(remote, local, protocol, pkt); err != nil {
				e.disconnect(id, vm.Conn)
				return err
			}

			atomic.AddUint64(&e.Sent, uint64(pkt.Size()))
		}
	} else {
		e.camLock.RLock()
		id, ok := e.cam[remote]
		if !ok {
			e.camLock.RUnlock()
			return nil
		}
		e.camLock.RUnlock()

		vm := e.conns[id]
		if err := vm.DeliverNetworkPacket(remote, local, protocol, pkt); err != nil {
			e.disconnect(id, vm.Conn)
			return err
		}

		atomic.AddUint64(&e.Sent, uint64(pkt.Size()))

	}
	return nil
}

func (e *Switch) disconnect(id int, conn net.Conn) {
	e.camLock.Lock()
	defer e.camLock.Unlock()

	for address, targetConn := range e.cam {
		if targetConn == id {
			delete(e.cam, address)
		}
	}
	_ = conn.Close()
	delete(e.conns, id)

	e.IPs.Release(id)
}

func (e *Switch) rx(id int, conn net.Conn) error {
	sizeBuf := make([]byte, 2)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			return errors.Wrap(err, "cannot read size from socket")
		}
		if n != 2 {
			return fmt.Errorf("unexpected size %d", n)
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		buf := make([]byte, size)
		n, err = io.ReadFull(conn, buf)
		if err != nil {
			return errors.Wrap(err, "cannot read packet from socket")
		}
		if n == 0 || n != size {
			return fmt.Errorf("unexpected size %d != %d", n, size)
		}

		if e.debug {
			packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
			log.Info(packet.String())
		}

		view := buffer.View(buf)
		eth := header.Ethernet(view)
		vv := buffer.NewVectorisedView(len(view), []buffer.View{view})

		e.camLock.Lock()
		e.cam[eth.SourceAddress()] = id
		e.camLock.Unlock()

		if eth.DestinationAddress() != e.gateway.LinkAddress() {
			if err := e.tx(eth.DestinationAddress(), eth.SourceAddress(), eth.Type(), stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: vv,
			})); err != nil {
				log.Error(err)
			}
		}
		if eth.DestinationAddress() == e.gateway.LinkAddress() || eth.DestinationAddress() == header.EthernetBroadcastAddress {
			vv.TrimFront(header.EthernetMinimumSize)
			e.gateway.DeliverNetworkPacket(
				eth.SourceAddress(),
				eth.DestinationAddress(),
				eth.Type(),
				stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}),
			)
		}

		atomic.AddUint64(&e.Received, uint64(size))
	}
}
