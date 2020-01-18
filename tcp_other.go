// +build !linux

package main

import (
	"context"
	"net"
)

func redirLocal(ctx context.Context, addr, server string, shadow func(net.Conn) net.Conn) {
	logf("TCP redirect not supported")
}

func redir6Local(ctx context.Context, addr, server string, shadow func(net.Conn) net.Conn) {
	logf("TCP6 redirect not supported")
}
