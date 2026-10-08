//Go:сборка Linux

package extensionhost

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
func terminateProcessTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	err := syscall.Kill(-p.Pid, syscall.SIGTERM)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
func killProcessTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	err := syscall.Kill(-p.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
func resourceIsolationMode() string { return "linux-process-group+proc-tree-rss+process-count" }

func processTreeUsage(rootPID int) (int64, int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, err
	}
	var rss int64
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		text := string(stat)
		end := strings.LastIndex(text, ")")
		if end < 0 {
			continue
		}
		fields := strings.Fields(text[end+1:])
		if len(fields) < 3 {
			continue
		}
		pgrp, err := strconv.Atoi(fields[2])
		if err != nil || pgrp != rootPID {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					kb, _ := strconv.ParseInt(parts[1], 10, 64)
					rss += kb * 1024
				}
				break
			}
		}
		count++
	}
	if count == 0 {
		return 0, 0, errors.New("группа процессов не found")
	}
	return rss, count, nil
}

// HardenBackendProcess предотвращает одинаковый-UID дочерний обрабатывает из подключение к 
// Серверная часть с ptrace или чтение его процесс память через procfs на Linux.
func HardenBackendProcess() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(4), uintptr(0), 0, 0, 0, 0) // PR_SET_DUMPABLE=0
	if errno != 0 {
		return errno
	}
	return nil
}
