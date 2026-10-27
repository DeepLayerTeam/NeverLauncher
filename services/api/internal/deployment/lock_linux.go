//go:build linux

package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// InstanceLock owns a filesystem-level flock until all HTTP/workers have stopped.
// Lockfiles are intentionally NEVER unlinked: removing a held inode would allow
// another process to create and lock a different inode at the same pathname.
type InstanceLock struct{ file *os.File }

func Acquire(plan Plan) (*InstanceLock, error) {
	if !plan.SingleInstance {
		return &InstanceLock{}, nil
	}
	path := plan.LockPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("instance lock requires an absolute clean path")
	}
	parent := filepath.Dir(path)
	// Never traverse symlinked segments: otherwise two names can resolve to
	// the same storage or the lock could point outside the intended volume.
	current := string(filepath.Separator)
	if parent != "/" {
		parts := splitPath(parent)
		for _, part := range parts {
			current = filepath.Join(current, part)
			st, e := os.Lstat(current)
			if os.IsNotExist(e) {
				if e = os.Mkdir(current, 0700); e == nil {
					st, e = os.Lstat(current)
				}
			}
			if e != nil {
				return nil, fmt.Errorf("instance lock parent %s: %w", current, e)
			}
			if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
				return nil, fmt.Errorf("instance lock parent %s must be a real directory", current)
			}
		}
	}
	st, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("instance lock parent is group/world-writable")
	}
	if plan.requireLocalFS {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("production instance lock parent must be owned by service user and mode 0700")
		}
		var fs syscall.Statfs_t
		if err := syscall.Statfs(parent, &fs); err != nil {
			return nil, err
		}
		switch fs.Type {
		case 0xef53, 0x58465342, 0x9123683e: // ext4, XFS, Btrfs
		default:
			return nil, fmt.Errorf("instance lock requires verified local ext4/XFS/Btrfs, got fs type 0x%x", fs.Type)
		}
		if fs.Flags&1 != 0 {
			return nil, errors.New("instance lock filesystem is read-only")
		}
	}
	// O_NOFOLLOW and O_CLOEXEC prevent symlink substitution and child inheritance.
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("instance lock open: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(e error) (*InstanceLock, error) { _ = file.Close(); return nil, e }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return fail(errors.New("instance lock requires owned regular 0600 file with one hard link"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("instance already running, lock %s: %w", path, err))
	}
	// Detect pathname replacement between open and lock.
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) {
		return fail(errors.New("instance lock pathname changed during acquisition"))
	}
	return &InstanceLock{file: file}, nil
}

func splitPath(path string) []string {
	rel, _ := filepath.Rel("/", path)
	if rel == "." {
		return nil
	}
	sep := string(filepath.Separator)
	var result []string
	for _, piece := range strings.Split(rel, sep) {
		if piece != "" && piece != "." {
			result = append(result, piece)
		}
	}
	return result
}

func (l *InstanceLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return errors.Join(syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
}
