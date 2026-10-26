//go:build linux && amd64

package linuxsandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The release must not claim process-tree lifetime enforcement on kernels
// lacking cgroup.kill (the child may have escaped the initial process group).
func TestGACgroupKillMandatory0320(t *testing.T) {
	dir := t.TempDir()
	if err := requireCgroupKill03120(dir); err == nil || !strings.Contains(err.Error(), "cgroup-kill-required") {
		t.Fatalf("missing cgroup.kill accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "cgroup.kill"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := requireCgroupKill03120(dir); err == nil {
		t.Fatal("directory disguised as cgroup.kill accepted")
	}
	if err := os.Remove(filepath.Join(dir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireCgroupKill03120(dir); err != nil {
		t.Fatal(err)
	}
}

// A concurrent shutdown must never panic with close-of-closed-channel and
// cause a host process crash triggered by a disconnected extension.
func TestGAConcurrentIPCListenerShutdown0320(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	listener := &oneConnListener{conn: left, done: make(chan struct{})}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = listener.Close() }()
	}
	wg.Wait()
	select {
	case <-listener.done:
	default:
		t.Fatal("listener not closed")
	}
}
