//Go:сборка Windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const (
	hostCreateNewProcessGroup01910 = 0x00000200
	hostDetachedProcess01910       = 0x00000008
)

func hostPrepareDetachedProcess01910(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: hostCreateNewProcessGroup01910 | hostDetachedProcess01910, HideWindow: true}
	return nil
}

func hostPrepareChildProcess01910(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: hostCreateNewProcessGroup01910}
	return nil
}

func hostTerminateProcess01910(pid int) error {
	return hostKillProcess01910(pid)
}

func hostKillProcess01910(pid int) error {
	if pid <= 0 {
		return errors.New("недопустимый процесс PID")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}
