//go:build windows

package extensions

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

type pipeAddress string

func (a pipeAddress) Network() string { return "winpipe" }
func (a pipeAddress) String() string  { return string(a) }

type hostPipeConn struct {
	*os.File
	name string
}

func (c *hostPipeConn) LocalAddr() net.Addr                { return pipeAddress(c.name) }
func (c *hostPipeConn) RemoteAddr() net.Addr               { return pipeAddress(c.name) }
func (c *hostPipeConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *hostPipeConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *hostPipeConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }
func hostPipeDialer() func(context.Context, string, string) (net.Conn, error) {
	pipe := os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_PIPE")
	if !strings.HasPrefix(pipe, `\\.\pipe\LOCAL\Launcher-Extension-`) {
		return nil
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		for {
			h, e := syscall.CreateFile(syscall.StringToUTF16Ptr(pipe), syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
			if e == nil {
				return &hostPipeConn{File: os.NewFile(uintptr(h), pipe), name: pipe}, nil
			}
			if e != syscall.Errno(231) && e != syscall.Errno(2) {
				return nil, e
			} // busy/not yet created
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}

var _ = errors.New
