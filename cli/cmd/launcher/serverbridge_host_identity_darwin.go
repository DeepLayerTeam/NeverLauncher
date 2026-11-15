//go:build darwin

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// KERN_PROC_PID returns kinfo_proc, whose extern_proc begins with the
// kernel-supplied process start timeval (Darwin 64-bit ABI). A PID alone is
// never accepted as process identity. Both seconds and microseconds are bound.
func hostProcessIdentity0282(pid int) (string, error) {
	if pid <= 0 || int64(pid) > 2147483647 {
		return "", fmt.Errorf("некорректный PID")
	}
	mib := [4]int32{1, 14, 1, int32(pid)} // CTL_KERN, KERN_PROC, KERN_PROC_PID
	var size uintptr
	_, _, e := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), 4, 0, uintptr(unsafe.Pointer(&size)), 0, 0)
	if e != 0 {
		return "", e
	}
	if size < 16 || size > 65536 {
		return "", fmt.Errorf("некорректный размер kinfo_proc: %d", size)
	}
	buf := make([]byte, size)
	_, _, e = syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), 4, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if e != 0 {
		return "", e
	}
	if size < 16 {
		return "", fmt.Errorf("процесс не найден")
	}
	tv := (*syscall.Timeval)(unsafe.Pointer(&buf[0]))
	if tv.Sec <= 0 || tv.Usec < 0 || tv.Usec >= 1000000 {
		return "", fmt.Errorf("некорректное время рождения процесса")
	}
	return fmt.Sprintf("darwin:%d:%d", tv.Sec, tv.Usec), nil
}
