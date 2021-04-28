package dhcp

import (
	"errors"
	"net"
	"time"

	"github.com/code-ready/gvisor-tap-vsock/pkg/tap"
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const serverPort = 67

func handler(configuration *types.Configuration, ipPool *tap.IPPool) server4.Handler {

	return func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
		reply, err := dhcpv4.NewReplyFromRequest(m)
		if err != nil {
			log.Errorf("dhcp: cannot build reply from request: %v", err)
			return
		}

		ip, _ := ipPool.Assign(m.ClientHWAddr.String())

		_, parsedSubnet, _ := net.ParseCIDR(configuration.Subnet)

		reply.YourIPAddr = ip
		reply.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(configuration.GatewayIP)))
		reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Hour))

		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpv4.IP(parsedSubnet.Mask)})
		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionRouter, Value: dhcpv4.IP(net.ParseIP(configuration.GatewayIP))})
		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionDomainNameServer, Value: dhcpv4.IPs([]net.IP{net.ParseIP(configuration.GatewayIP)})})
		reply.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionInterfaceMTU, Value: dhcpv4.Uint16(configuration.MTU)})

		switch mt := m.MessageType(); mt {
		case dhcpv4.MessageTypeDiscover:
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		case dhcpv4.MessageTypeRequest:
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
		default:
			log.Errorf("dhcp: unhandled message type: %v", mt)
			return
		}

		if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
			log.Errorf("dhcp: cannot reply to client: %v", err)
		}
	}
}

func Dial(s *stack.Stack, nic int) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	ep.SocketOptions().SetBroadcast(true)

	if err := ep.Bind(tcpip.FullAddress{
		NIC:  tcpip.NICID(nic),
		Addr: "",
		Port: uint16(serverPort),
	}); err != nil {
		ep.Close()
		return nil, errors.New(err.String())
	}

	return gonet.NewUDPConn(s, &wq, ep), nil
}

func Serve(c net.PacketConn, configuration *types.Configuration, ipPool *tap.IPPool) error {
	server, err := server4.NewServer("", nil, handler(configuration, ipPool), server4.WithConn(c))
	if err != nil {
		return err
	}

	return server.Serve()
}
