//go:build darwin

package extensions

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
)

// One inherited Unix socketpair is the ONLY route to the host in App Sandbox.
// The HTTP transport must reuse this connection; a closed connection fails
// closed instead of opening a loopback TCP route.
func hostPipeDialer() func(context.Context, string, string) (net.Conn, error) {
	fd, err := strconv.Atoi(os.Getenv("LAUNCHER_EXTENSION_HOST_FD"))
	if err != nil || fd != 4 {
		return nil
	}
	var once sync.Once
	var conn net.Conn
	var initErr error
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		first := false
		once.Do(func() {
			first = true
			f := os.NewFile(uintptr(fd), "sandbox-host-ipc")
			conn, initErr = net.FileConn(f)
			_ = f.Close()
		})
		if !first {
			return nil, errors.New("sandbox-host-socket-already-consumed")
		}
		return conn, initErr
	}
}
