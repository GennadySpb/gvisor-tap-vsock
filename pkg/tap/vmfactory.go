package tap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	log "github.com/sirupsen/logrus"
)

type VirtualMachineFactory struct {
	MTU       int
	GatewayIP string
	IPs       *IPPool
}

func (factory *VirtualMachineFactory) handshake(id int, conn net.Conn) (*VirtualMachine, error) {
	ip, err := factory.IPs.Assign(id)
	if err != nil {
		return nil, err
	}

	log.Infof("assigning %s to %s", ip, conn.RemoteAddr().String())
	bin, err := json.Marshal(&types.Handshake{
		MTU:     factory.MTU,
		Gateway: factory.GatewayIP,
		VM:      fmt.Sprintf("%s/%d", ip, factory.IPs.Mask()),
	})
	if err != nil {
		return nil, err
	}
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(len(bin)))
	if _, err := conn.Write(size); err != nil {
		return nil, err
	}
	if _, err := conn.Write(bin); err != nil {
		return nil, err
	}
	return &VirtualMachine{
		ID:   id,
		Conn: conn,
	}, nil
}
