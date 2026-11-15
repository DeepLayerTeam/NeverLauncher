//go:build !windows

package discordrpc

import (
	"net"
	"path/filepath"
	"testing"
)

type unixTestListener struct{ net.Listener }

func (l unixTestListener) Accept() (testIPCConn, error) { return l.Listener.Accept() }
func newTestIPCListener(t *testing.T, _ int) (testIPCListener, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "discord-ipc-0")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return unixTestListener{l}, []string{path}
}
