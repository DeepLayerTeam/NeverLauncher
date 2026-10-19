//go:build windows

package prestarter

import (
	"os"
	"syscall"
	"unsafe"
)

type processLock struct{ file *os.File }

var k32 = syscall.NewLazyDLL("kernel32.dll")
var lockFileEx = k32.NewProc("LockFileEx")
var unlockFileEx = k32.NewProc("UnlockFileEx")

func acquireProcessLock(path string) (*processLock, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	var overlap syscall.Overlapped
	// LOCKFILE_EXCLUSIVE_LOCK, 1 byte starting at zero.
	r, _, err := lockFileEx.Call(f.Fd(), 2, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if r == 0 {
		f.Close()
		return nil, err
	}
	return &processLock{file: f}, nil
}
func (l *processLock) Close() error {
	var overlap syscall.Overlapped
	unlockFileEx.Call(l.file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	return l.file.Close()
}
