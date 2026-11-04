//go:build !linux

package sqlitedurable

import (
	"errors"
	"os"
)

// Проверки блокировок/сброса на диск DEP00 GA пока охватывают только Linux
// ext4/xfs/btrfs. Отклонять другие ОС, а не заявлять о непроверенных гарантиях.
func verifyLocalPath(string) error {
	return errors.New("SQLite durable filesystem and process fencing not certified on this OS")
}
func exclusiveLock(string) (*os.File, error) {
	return nil, errors.New("unsupported SQLite filesystem locking")
}
func releaseLock(*os.File) error          { return nil }
func durableFileSystemProbe(string) error { return errors.New("unsupported SQLite fsync semantics") }
