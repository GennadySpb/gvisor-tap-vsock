package tap

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Protocol int

const HelperContainerProtocol Protocol = 2
const QemuProtocol Protocol = 4

type VirtualMachineFactory struct {
	MTU           int
	GatewayIP     string
	IPs           *IPPool
	Debug         bool
	NetworkSwitch NetworkSwitch

	Protocol Protocol
}

func (factory *VirtualMachineFactory) Accept(conn net.Conn) {
	log.Infof("new connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	id := factory.NetworkSwitch.FreePort()

	vm, err := factory.handshake(id, conn)
	if err != nil {
		log.Errorf("connection failed: %v", err)
		return
	}
	defer vm.Close()

	factory.NetworkSwitch.ConnectVM(vm.ID, vm)
	defer factory.NetworkSwitch.Disconnect(vm)

	if err := vm.rx(); err != nil {
		log.Error(errors.Wrapf(err, "cannot receive packets from %s, disconnecting", conn.RemoteAddr().String()))
		return
	}
}

func (factory *VirtualMachineFactory) handshake(id int, conn net.Conn) (*VirtualMachine, error) {
	if factory.Protocol == HelperContainerProtocol {
		ip, err := factory.IPs.Assign(strconv.Itoa(id))
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
		size := sizePayload(factory.Protocol, len(bin))
		if _, err := conn.Write(size); err != nil {
			return nil, err
		}
		if _, err := conn.Write(bin); err != nil {
			return nil, err
		}
	}

	return &VirtualMachine{
		ID:            id,
		Conn:          conn,
		Debug:         factory.Debug,
		NetworkSwitch: factory.NetworkSwitch,
		Protocol:      factory.Protocol,
		OnClose: func() {
			if factory.Protocol == HelperContainerProtocol {
				factory.IPs.Release(strconv.Itoa(id))
			}
		},
	}, nil
}
