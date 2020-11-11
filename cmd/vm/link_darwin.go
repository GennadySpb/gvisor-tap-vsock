package main

import (
	"github.com/code-ready/gvisor-tap-vsock/pkg/types"
)

const deviceType = types.TUN

func linkUp(handshake *types.HandshakeResponse) (func(), error) {
	return func() {
	}, nil
}
