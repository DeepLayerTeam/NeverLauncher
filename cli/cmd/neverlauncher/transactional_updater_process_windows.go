//go:build windows

package main

import "syscall"

var updaterKernel320156 = syscall.NewLazyDLL("kernel32.dll")
var updaterOpenProcess0156 = updaterKernel320156.NewProc("OpenProcess")
var updaterCloseHandle0156 = updaterKernel320156.NewProc("CloseHandle")

func updaterProcessAlive0156(pid int) bool {
	if pid <= 0 {
		return false
	}
	const processQueryLimitedInformation = 0x1000
	handle, _, callErr := updaterOpenProcess0156.Call(processQueryLimitedInformation, 0, uintptr(uint32(pid)))
	if handle == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_ACCESS_DENIED {
			return true
		}
		return false
	}
	_, _, _ = updaterCloseHandle0156.Call(handle)
	return true
}
