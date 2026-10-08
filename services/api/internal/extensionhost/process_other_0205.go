//Go:сборка!Linux

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

// HardenBackendProcess является платформа хук. Linux применяет PR_SET_DUMPABLE=0;
// другой платформы сохранять процесс separation и секрет-free окружение.
func HardenBackendProcess() error { return nil }
