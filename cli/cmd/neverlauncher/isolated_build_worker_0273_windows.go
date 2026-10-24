//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func limitWorkerResources0273(seconds int) error { return nil }
func prepareWorkerProcess0273(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
func prepareJavaChild0273(cmd *exec.Cmd) {}
func terminateWorkerTree0273(p *os.Process) {
	if p == nil {
		return
	}
	// taskkill /T terminates child processes as well as the build worker.
	_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(p.Pid)).Run()
	_ = p.Kill()
}
func strictSandboxJavaCommand0273(_ context.Context, _ processorWorkerRequest0273, _ []string) (*exec.Cmd, error) {
	return nil, errors.New("strict processor sandbox requires Linux bubblewrap")
}
