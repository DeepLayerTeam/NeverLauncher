//go:build !linux

package extensionhost

import (
	"os"
	"os/exec"
)

func configureProcess(cmd *exec.Cmd) {}
func terminateProcessTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Signal(os.Interrupt)
}
func killProcessTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}
func resourceIsolationMode() string                { return "single-process+protocol-bounds" }
func processTreeUsage(pid int) (int64, int, error) { return 0, 1, nil }

// HardenBackendProcess is a platform hook. Linux enforces PR_SET_DUMPABLE=0;
// other platforms retain the process separation and secret-free environment.
func HardenBackendProcess() error { return nil }
