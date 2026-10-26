//go:build !windows

package neverextensions

import (
	"context"
	"net"
)

func hostPipeDialer() func(context.Context, string, string) (net.Conn, error) { return nil }
