package tap

import (
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	FreePort() int
	DeliverNetworkPacketWithPort(port int, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
	ConnectVM(port int, vm *VirtualMachine)
	Disconnect(vm *VirtualMachine)
}

const gatewayPort = -1

type Switch struct {
	Sent     uint64
	Received uint64

	debug               bool
	maxTransmissionUnit int

	nextConnID     int
	nextConnIDLock sync.Mutex

	conns    map[int]*VirtualMachine
	connLock sync.Mutex

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

func (e *Switch) ConnectVM(port int, vm *VirtualMachine) {
	e.connLock.Lock()
	defer e.connLock.Unlock()
	e.conns[port] = vm
}

func (e *Switch) Disconnect(vm *VirtualMachine) {
	e.camLock.Lock()
	defer e.camLock.Unlock()

	for address, targetConn := range e.cam {
		if targetConn == vm.ID {
			delete(e.cam, address)
		}
	}

	e.connLock.Lock()
	defer e.connLock.Unlock()
	delete(e.conns, vm.ID)

	_ = vm.Close()
}

func (e *Switch) FreePort() int {
	e.nextConnIDLock.Lock()
	defer e.nextConnIDLock.Unlock()

	id := e.nextConnID
	e.nextConnID++
	return id
}

func (e *Switch) DeliverNetworkPacketWithPort(id int, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if e.debug {
		debugPkt := pkt.Clone()
		eth := header.Ethernet(debugPkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			Type:    protocol,
			SrcAddr: local,
			DstAddr: remote,
		})
		vv := buffer.NewVectorisedView(debugPkt.Size(), debugPkt.Views())
		packet := gopacket.NewPacket(vv.ToView(), layers.LayerTypeEthernet, gopacket.Default)
		log.Info(packet.String())
	}

	e.camLock.Lock()
	e.cam[local] = id
	e.camLock.Unlock()

	// send packets to VMs
	if remote != e.gateway.LinkAddress() {
		if err := e.sendVMs(remote, local, protocol, pkt); err != nil {
			log.Error(err)
		}
	}
	// then, send packets to the gateway
	if remote == e.gateway.LinkAddress() || (remote == header.EthernetBroadcastAddress && local != e.gateway.LinkAddress()) {
		e.gateway.DeliverNetworkPacket(
			local,
			remote,
			protocol,
			pkt,
		)
	}

	atomic.AddUint64(&e.Received, uint64(pkt.Size()))
}

func (e *Switch) sendVMs(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) error {
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
			if err := vm.DeliverNetworkPacket(remote, local, protocol, pkt.Clone()); err != nil {
				e.Disconnect(vm)
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
			e.Disconnect(vm)
			return err
		}

		atomic.AddUint64(&e.Sent, uint64(pkt.Size()))

	}
	return nil
}
