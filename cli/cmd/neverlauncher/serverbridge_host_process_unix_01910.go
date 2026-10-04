//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func hostPrepareDetachedProcess01910(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return nil
}

func hostPrepareChildProcess01910(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func hostTerminateProcess01910(pid int) error {
	if pid <= 0 {
		return errors.New("invalid process pid")
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func hostKillProcess01910(pid int) error {
	if pid <= 0 {
		return errors.New("invalid process pid")
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		if process, findErr := os.FindProcess(pid); findErr == nil {
			return process.Kill()
		}
		return err
	}
	return nil
}
