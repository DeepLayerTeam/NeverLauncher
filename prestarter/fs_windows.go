//go:build windows

package prestarter

import (
	"fmt"
	"syscall"
	"unsafe"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func atomicReplace(from, to string) error {
	src, e := syscall.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	dst, e := syscall.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH; no delete-then-rename gap.
	done, _, err := moveFileEx.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 0x1|0x8)
	if done == 0 {
		return fmt.Errorf("MoveFileExW: %w", err)
	}
	return nil
}
func syncDir(path string) error { return nil } // filesystem metadata durability is provided by MOVEFILE_WRITE_THROUGH on Windows
