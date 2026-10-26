//go:build !windows && !darwin

package neverextensions

import (
	"context"
	"net"
)

func hostPipeDialer() func(context.Context, string, string) (net.Conn, error) { return nil }
