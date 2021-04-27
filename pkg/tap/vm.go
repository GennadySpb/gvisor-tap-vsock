package tap

import (
	"encoding/binary"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualMachine struct {
	ID   int
	Conn net.Conn

	writeLock sync.Mutex // one packet write at a time
}

func (vm *VirtualMachine) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) error {
	vm.writeLock.Lock()
	defer vm.writeLock.Unlock()

	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(pkt.Size()))

	if _, err := vm.Conn.Write(size); err != nil {
		return err
	}
	for _, view := range pkt.Views() {
		if _, err := vm.Conn.Write(view); err != nil {
			return err
		}
	}
	return nil
}
