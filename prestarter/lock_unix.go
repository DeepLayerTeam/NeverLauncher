//go:build !windows

package prestarter

import (
	"os"
	"syscall"
)

type processLock struct{ file *os.File }

func acquireProcessLock(path string) (*processLock, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return &processLock{f}, nil
}
func (l *processLock) Close() error {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
