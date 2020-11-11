package main

import (
	"net"

	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const deviceType = types.TAP

func linkUp(handshake *types.HandshakeResponse) (func(), error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return func() {}, err
	}
	newDefaultRoute := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        net.ParseIP(handshake.Gateway),
	}
	addr, err := netlink.ParseAddr(handshake.VM)
	if err != nil {
		return func() {}, err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return func() {}, errors.Wrap(err, "cannot add address")
	}
	if err := netlink.LinkSetMTU(link, handshake.MTU); err != nil {
		return func() {}, errors.Wrap(err, "cannot set link mtu")
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return func() {}, errors.Wrap(err, "cannot set link up")
	}

	if !changeDefaultRoute {
		return func() {}, nil
	}
	defaultRoute, err := defaultRoute()
	if err != nil {
		log.Warn(err)
	}
	cleanup := func() {
		if err := netlink.RouteDel(&newDefaultRoute); err != nil {
			log.Errorf("cannot remove new default gateway: %v", err)
		}
		if defaultRoute != nil {
			if err := netlink.RouteAdd(defaultRoute); err != nil {
				log.Errorf("cannot restore old default gateway: %v", err)
			}
		}
	}
	if defaultRoute != nil {
		if err := netlink.RouteDel(defaultRoute); err != nil {
			return cleanup, errors.Wrap(err, "cannot remove old default gateway")
		}
	}
	if err := netlink.RouteAdd(&newDefaultRoute); err != nil {
		return cleanup, errors.Wrap(err, "cannot add new default gateway")
	}
	return cleanup, nil
}

func defaultRoute() (*netlink.Route, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst == nil {
			return &r, nil
		}
	}
	return nil, errors.New("no default gateway found")
}
