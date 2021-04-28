package tap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualMachine struct {
	ID    int
	Conn  net.Conn
	Debug bool

	Protocol Protocol

	NetworkSwitch NetworkSwitch

	writeLock sync.Mutex // one packet write at a time

	OnClose func()
}

func (vm *VirtualMachine) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) error {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    protocol,
		SrcAddr: local,
		DstAddr: remote,
	})

	vm.writeLock.Lock()
	defer vm.writeLock.Unlock()

	size := sizePayload(vm.Protocol, pkt.Size())

	if _, err := vm.Conn.Write(size); err != nil {
		_ = vm.Close()
		return err
	}
	for _, view := range pkt.Views() {
		if _, err := vm.Conn.Write(view); err != nil {
			_ = vm.Close()
			return err
		}
	}
	return nil
}

func (vm *VirtualMachine) rx() error {
	sizeBuf := make([]byte, sizeSize(vm.Protocol))

	for {
		n, err := io.ReadFull(vm.Conn, sizeBuf)
		if err != nil {
			return errors.Wrap(err, "cannot read size from socket")
		}
		if n != sizeSize(vm.Protocol) {
			return fmt.Errorf("unexpected size %d", n)
		}
		size := readSize(vm.Protocol, sizeBuf)

		buf := make([]byte, size)
		n, err = io.ReadFull(vm.Conn, buf)
		if err != nil {
			return errors.Wrap(err, "cannot read packet from socket")
		}
		if n == 0 || n != size {
			return fmt.Errorf("unexpected size %d != %d", n, size)
		}

		view := buffer.View(buf)
		eth := header.Ethernet(view)
		view.TrimFront(header.EthernetMinimumSize)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: header.EthernetMinimumSize,
			Data:               buffer.NewVectorisedView(len(view), []buffer.View{view}),
		})

		vm.NetworkSwitch.DeliverNetworkPacketWithPort(vm.ID, eth.DestinationAddress(), eth.SourceAddress(), eth.Type(), pkt)
	}
}

func readSize(protocol Protocol, sizeBuf []byte) int {
	if protocol == QemuProtocol {
		return int(binary.BigEndian.Uint32(sizeBuf[0:int(protocol)]))
	}
	return int(binary.LittleEndian.Uint16(sizeBuf[0:int(protocol)]))
}

func sizePayload(protocol Protocol, i int) []byte {
	size := make([]byte, int(protocol))
	if protocol == QemuProtocol {
		binary.BigEndian.PutUint32(size, uint32(i))
	} else {
		binary.LittleEndian.PutUint16(size, uint16(i))
	}
	return size
}

func sizeSize(protocol Protocol) int {
	return int(protocol)
}

func (vm *VirtualMachine) Close() error {
	if vm.OnClose != nil {
		vm.OnClose()
	}
	return vm.Conn.Close()
}
