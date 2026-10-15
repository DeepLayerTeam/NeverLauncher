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

// HardenBackendProcess — платформенный обработчик. Linux применяет PR_SET_DUMPABLE=0;
// другие платформы сохраняют разделение процессов и окружение без секретов.
func HardenBackendProcess() error { return nil }
