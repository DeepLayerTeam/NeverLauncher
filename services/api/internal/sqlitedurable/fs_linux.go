//go:build linux

package sqlitedurable

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	fsEXT4  = 0xef53
	fsXFS   = 0x58465342
	fsBTRFS = 0x9123683e
)

func verifyLocalPath(path string) error {
	if path == "/" {
		return errors.New("sqlite database path cannot be root")
	}
	dir := filepath.Dir(path)
	if err := rejectSymlinkSegments(dir); err != nil {
		return err
	}
	// Existing directory permissions are checked, not silently weakened.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("sqlite directory must be a real directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("sqlite directory %s permissions %04o unsafe; use chmod 0700", dir, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("sqlite directory must be owned by service user")
	}
	if err = rejectSymlinkSegments(dir); err != nil {
		return err
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(dir, &fs); err != nil {
		return err
	}
	switch fs.Type {
	case fsEXT4, fsXFS, fsBTRFS:
	default:
		return fmt.Errorf("unsupported SQLite filesystem 0x%x: only verified local ext4/xfs/btrfs; reject overlay/NFS/SMB/tmpfs", fs.Type)
	}
	if fs.Flags&1 /* ST_RDONLY on Linux */ != 0 {
		return errors.New("sqlite filesystem is read-only")
	}
	if f, e := os.Lstat(path); e == nil {
		if !f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 {
			return errors.New("sqlite file must be regular and a symlink")
		}
		if f.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("sqlite file permissions %04o unsafe", f.Mode().Perm())
		}
		if st, ok := f.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
			return errors.New("sqlite database ownership mismatch")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}

func rejectSymlinkSegments(dir string) error {
	current := "/"
	rel, err := filepath.Rel("/", dir)
	if err != nil {
		return err
	}
	for _, part := range splitPath(rel) {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sqlite path has symlink component %s", current)
		}
	}
	return nil
}

func splitPath(s string) []string {
	if s == "." {
		return nil
	}
	return strings.Split(s, string(filepath.Separator))
}

func exclusiveLock(name string) (*os.File, error) {
	fd, err := syscall.Open(name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("sqlite owner lock open: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		err = errors.New("sqlite owner lock must be regular and mode 0600")
	}
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			err = errors.New("sqlite owner lock must belong to service user")
		}
	}
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sqlite DB owned by another instance or unsafe lock: %w", err)
	}
	return f, nil
}

func releaseLock(f *os.File) error {
	if f == nil {
		return nil
	}
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return errors.Join(err, f.Close())
}

func durableFileSystemProbe(dir string) error {
	tmp, err := os.CreateTemp(dir, ".dep00-durable-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if _, err = io.WriteString(tmp, "launcher-sqlite-durable-fs-v1"); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	target := name + ".renamed"
	defer os.Remove(target)
	if err = os.Rename(name, target); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err = directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	if err = directory.Close(); err != nil {
		return err
	}
	if err = os.Remove(target); err != nil {
		return err
	}
	directory, err = os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}
