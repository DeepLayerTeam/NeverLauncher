//go:build linux && amd64

package linuxsandbox

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Requires a delegated cgroup v2 and working unprivileged namespaces. Unlike
// a mock, this test launches the actual sandbox and verifies that a child
// spawned into a different process group cannot survive cgroup.kill.
func TestLinuxAdversarialDescendants03114(t *testing.T) {
	if os.Getenv("NL_RUN_LIVE_LINUX_SANDBOX") != "1" {
		t.Skip("live kernel host explicitly required")
	}
	if err := Available(); err != nil {
		t.Fatalf("required live sandbox unavailable: %v", err)
	}
	opt := validOptions0319(t)
	opt.Policy.MaxProcesses = 8
	opt.Policy.TimeoutSeconds = 20
	script := `#!/bin/sh
set -eu
# Both leader and descendant must remain in the same OS cgroup even if a
# child creates a fresh process group. A process group alone is not security.
setsid /bin/sh -c 'sleep 15' >/dev/null 2>&1 &
echo descendant-started
sleep 15
`
	if err := os.WriteFile(opt.Entrypoint, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h, err := Prepare(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var stderr bytes.Buffer
	h.Cmd.Stderr = &stderr
	if err := h.Cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.Started(); err != nil {
		t.Fatalf("OS sandbox init: %v / %s", err, stderr.String())
	}
	var descendants []int
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		b, err := os.ReadFile(h.cgroup + "/cgroup.procs")
		if err != nil {
			t.Fatal(err)
		}
		descendants = descendants[:0]
		for _, raw := range strings.Fields(string(b)) {
			if pid, e := strconv.Atoi(raw); e == nil {
				descendants = append(descendants, pid)
			}
		}
		if len(descendants) >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(descendants) < 3 {
		t.Fatalf("expected sandbox leader, proxy and descendant in one cgroup; got %v; %s", descendants, stderr.String())
	}
	h.Close()
	deadline := time.Now().Add(3 * time.Second)
	for _, pid := range descendants {
		for {
			err := syscall.Kill(pid, 0)
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			// Zombies have exited, and cannot execute even before reap.
			status, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
			if readErr != nil || strings.Contains(string(status), "State:\tZ") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("descendant process %d survived sandbox close", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	_ = h.Cmd.Wait()
}
