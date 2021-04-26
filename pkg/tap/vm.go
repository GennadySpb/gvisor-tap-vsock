package tap

import "net"

type VirtualMachine struct {
	ID   int
	Conn net.Conn
}
