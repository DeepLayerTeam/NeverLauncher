//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func limitWorkerResources0273(seconds int) error {
	for _, limit := range []struct {
		resource int
		value    uint64
	}{
		{syscall.RLIMIT_CPU, uint64(seconds + 3)},
		{syscall.RLIMIT_FSIZE, 2 << 30},
		{syscall.RLIMIT_NOFILE, 1024},
		{syscall.RLIMIT_CORE, 0},
	} {
		var old syscall.Rlimit
		if err := syscall.Getrlimit(limit.resource, &old); err != nil {
			return err
		}
		value := limit.value
		if old.Max < value {
			value = old.Max
		}
		if err := syscall.Setrlimit(limit.resource, &syscall.Rlimit{Cur: value, Max: old.Max}); err != nil {
			return err
		}
	}
	return nil
}
func prepareWorkerProcess0273(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func prepareJavaChild0273(cmd *exec.Cmd)     {}
func terminateWorkerTree0273(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
func strictSandboxJavaCommand0273(_ context.Context, _ processorWorkerRequest0273, _ []string) (*exec.Cmd, error) {
	return nil, errors.New("strict processor sandbox requires Linux bubblewrap")
}
