//go:build linux

package sqlitepg

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func publishNewDirectory0377(src, dest string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dest))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
