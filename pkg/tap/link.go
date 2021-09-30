package tap

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LinkEndpoint struct {
	debug      bool
	mtu        int
	mac        tcpip.LinkAddress
	ip         string
	virtualIPs map[string]struct{}

	dispatcher    stack.NetworkDispatcher
	networkSwitch NetworkSwitch
}

func NewLinkEndpoint(debug bool, mtu int, macAddress string, ip string, virtualIPs []string) (*LinkEndpoint, error) {
	linkAddr, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{})
	for _, virtualIP := range virtualIPs {
		set[virtualIP] = struct{}{}
	}
	return &LinkEndpoint{
		debug:      debug,
		mtu:        mtu,
		mac:        tcpip.LinkAddress(linkAddr),
		ip:         ip,
		virtualIPs: set,
	}, nil
}

func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (e *LinkEndpoint) Connect(networkSwitch NetworkSwitch) {
	e.networkSwitch = networkSwitch
}

func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *LinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *LinkEndpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(remote, local, protocol, pkt)
}

func (e *LinkEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
}

func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired | stack.CapabilityRXChecksumOffload
}

func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.mac
}

func (e *LinkEndpoint) MaxHeaderLength() uint16 {
	return uint16(header.EthernetMinimumSize)
}

func (e *LinkEndpoint) MTU() uint32 {
	return uint32(e.mtu)
}

func (e *LinkEndpoint) Wait() {
}

func (e *LinkEndpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	return 1, &tcpip.ErrNoRoute{}
}

func (e *LinkEndpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	// Preserve the src address if it's set in the route.
	srcAddr := e.LinkAddress()
	if r.LocalLinkAddress != "" {
		srcAddr = r.LocalLinkAddress
	}
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    protocol,
		SrcAddr: srcAddr,
		DstAddr: r.RemoteLinkAddress,
	})

	h := header.ARP(pkt.NetworkHeader().View())
	if h.IsValid() &&
		h.Op() == header.ARPReply {
		ip := tcpip.Address(h.ProtocolAddressSender()).String()
		_, ok := e.virtualIPs[ip]
		if ip != e.IP() && !ok {
			log.Debugf("dropping spoofing packets from the gateway about IP %s", ip)
			return nil
		}
	}

	if e.debug {
		vv := buffer.NewVectorisedView(pkt.Size(), pkt.Views())
		packet := gopacket.NewPacket(vv.ToView(), layers.LayerTypeEthernet, gopacket.Default)
		if strings.Contains(packet.String(), "IPv6") {
			log.Info(packet.String())
		}
	}

	if pkt.NetworkProtocolNumber == ipv6.ProtocolNumber && pkt.TransportProtocolNumber == icmp.ProtocolNumber6 {
		h1 := header.ICMPv6(pkt.TransportHeader().View())
		fmt.Println("IPV6")
		if h1.Type() == header.ICMPv6NeighborAdvert {
			fmt.Println("ADVERT")
			ip := header.NDPNeighborAdvert(h1.MessageBody()).TargetAddress().String()
			fmt.Println(ip)
			if !strings.HasPrefix(ip, "fe80::1") && ip != "fd00::100" {
				log.Errorf("dropping spoofing packets from the gateway about IP %s", ip)
				return nil
			}
		}
	}

	e.networkSwitch.DeliverNetworkPacket(r.RemoteLinkAddress, srcAddr, protocol, pkt)
	return nil
}

func (e *LinkEndpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (e *LinkEndpoint) IP() string {
	return e.ip
}

// raBuf returns a valid NDP Router Advertisement with options, router
// preference and DHCPv6 configurations specified.
func raBuf(src, dst tcpip.LinkAddress, ip tcpip.Address, rl uint16, managedAddress, otherConfigurations bool, prf header.NDPRoutePreference, optSer header.NDPOptionsSerializer) *stack.PacketBuffer {
	const flagsByte = 1
	const routerLifetimeOffset = 2

	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + optSer.Length()
	hdr := buffer.NewPrependable(header.EthernetMinimumSize + header.IPv6MinimumSize + icmpSize)
	pkt := header.ICMPv6(hdr.Prepend(icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	raPayload := pkt.MessageBody()
	ra := header.NDPRouterAdvert(raPayload)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(raPayload[routerLifetimeOffset:], rl)
	// Populate the Managed Address flag field.
	if managedAddress {
		// The Managed Addresses flag field is the 7th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 7
	}
	// Populate the Other Configurations flag field.
	if otherConfigurations {
		// The Other Configurations flag field is the 6th bit of the flags byte.
		raPayload[flagsByte] |= 1 << 6
	}
	// The Prf field is held in the flags byte.
	raPayload[flagsByte] |= byte(prf) << 3
	opts := ra.Options()
	opts.Serialize(optSer)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    ip,
		Dst:    header.IPv6AllNodesMulticastAddress,
	}))
	payloadLength := hdr.UsedLength()
	iph := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           ip,
		DstAddr:           header.IPv6AllNodesMulticastAddress,
	})

	eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    ipv6.ProtocolNumber,
		SrcAddr: src,
		DstAddr: dst,
	})
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	})
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(src, dst tcpip.LinkAddress, ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) *stack.PacketBuffer {
	return raBuf(src, dst, ip, rl, false /* managedAddress */, false /* otherConfigurations */, 0 /* prf */, optSer)
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBufSimple(src, dst tcpip.LinkAddress, ip tcpip.Address, rl uint16) *stack.PacketBuffer {
	opts := header.NDPOptionsSerializer{}
	return raBufWithOpts(src, dst, ip, rl, opts)
}
