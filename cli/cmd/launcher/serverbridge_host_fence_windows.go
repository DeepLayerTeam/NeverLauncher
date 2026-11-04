//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var remoteKernel32Lock04112 = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
var remoteKernel32Unlock04112 = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")

// A stable, held-open Windows file handle is the cross-process fence.
// LOCKFILE_FAIL_IMMEDIATELY refuses a competing process instead of waiting.
func remoteKernelFence04112(dir string) (func(), error) {
	if err := remoteSecureDir0284(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "agent.fence")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("unsafe agent fence file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	overlap := &syscall.Overlapped{}
	ret, _, callErr := remoteKernel32Lock04112.Call(f.Fd(), 0x3, 0, 1, 0, uintptr(unsafe.Pointer(overlap)))
	if ret == 0 {
		_ = f.Close()
		return nil, fmt.Errorf("another RemoteControl process owns the kernel fence: %w", callErr)
	}
	return func() {
		remoteKernel32Unlock04112.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(overlap)))
		_ = f.Close()
	}, nil
}
