//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Нельзя переименовывать или удалять agent.fence во время работы агента: flock привязан к inode.
// Сохраняйте постоянный приватный файл, а не временный путь блокировки.
func remoteKernelFence04112(dir string) (func(), error) {
	path := filepath.Join(dir, "agent.fence")
	if err := remoteSecureDir0284(dir); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("Небезопасный файл блокировки агента")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another RemoteControl instance owns the kernel fence: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
