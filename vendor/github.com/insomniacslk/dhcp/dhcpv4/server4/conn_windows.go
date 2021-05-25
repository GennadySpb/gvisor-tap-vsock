package server4

import (
	"errors"
	"net"
)

func NewIPv4UDPConn(iface string, addr *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errors.New("not implemented on Windows")
}
