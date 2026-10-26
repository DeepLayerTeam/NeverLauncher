//go:build !linux

package sqlitedurable

import (
	"errors"
	"os"
)

// DEP00 GA filesystem locking/flush verification currently covers Linux
// ext4/xfs/btrfs only. Refuse other OS rather than claim untested guarantees.
func verifyLocalPath(string) error {
	return errors.New("SQLite durable filesystem and process fencing not certified on this OS")
}
func exclusiveLock(string) (*os.File, error) {
	return nil, errors.New("unsupported SQLite filesystem locking")
}
func releaseLock(*os.File) error          { return nil }
func durableFileSystemProbe(string) error { return errors.New("unsupported SQLite fsync semantics") }
