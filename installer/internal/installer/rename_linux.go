//go:build linux && amd64

package installer

import "syscall"
import "unsafe"

// Системный вызов renameat2: RENAME_NOREPLACE предотвращает гонки между конкурентными установщиками.
func noReplace(from, to string) error {
	a, err := syscall.BytePtrFromString(from)
	if err != nil {
		return err
	}
	b, err := syscall.BytePtrFromString(to)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(316, uintptr(^uint(99)), uintptr(unsafe.Pointer(a)), uintptr(^uint(99)), uintptr(unsafe.Pointer(b)), 1, 0)
	if e != 0 {
		return e
	}
	return nil
}
