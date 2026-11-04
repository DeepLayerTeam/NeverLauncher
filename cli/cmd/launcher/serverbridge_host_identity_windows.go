//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const hostProcessQueryLimitedInformation0282 = 0x1000

var hostKernel320282 = syscall.NewLazyDLL("kernel32.dll")
var hostGetProcessTimes0282 = hostKernel320282.NewProc("GetProcessTimes")
var hostOpenProcess0282 = hostKernel320282.NewProc("OpenProcess")
var hostCloseHandle0282 = hostKernel320282.NewProc("CloseHandle")

func hostProcessIdentity0282(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid")
	}
	h, _, e := hostOpenProcess0282.Call(hostProcessQueryLimitedInformation0282, 0, uintptr(uint32(pid)))
	if h == 0 {
		return "", e
	}
	defer hostCloseHandle0282.Call(h)
	var creation, exit, kernel, user syscall.Filetime
	ok, _, e := hostGetProcessTimes0282.Call(h, uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		return "", e
	}
	return fmt.Sprintf("%08x:%08x", creation.HighDateTime, creation.LowDateTime), nil
}
