//go:build linux

// Package extensionbroker implements host-side, scoped filesystem and network
// gates for OS-isolated NeverExtensions. It does not expose host paths or FDs.
package extensionbroker

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var resource = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Roots are trusted operator configuration, NOT values from an extension.
// Each name is the target of a signed shared:<name> grant. Every path
// component must be a real directory, not a symlink.
func ParseRoots(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var roots map[string]string
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&roots); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid roots JSON tail")
	}
	if len(roots) > 64 {
		return nil, ErrDenied
	}
	for name, path := range roots {
		if !resource.MatchString(name) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || path == "/" {
			return nil, fmt.Errorf("invalid shared root %q: %w", name, ErrDenied)
		}
		f, err := openDirectory(path)
		if err != nil {
			return nil, fmt.Errorf("shared root %q unavailable: %w", name, err)
		}
		_ = f.Close()
	}
	return roots, nil
}

// OpenDirectory walks from / using O_NOFOLLOW on every component. This
// excludes symlinked root parents, unlike os.Open(path) + filepath.EvalSymlinks.
func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrDenied
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, comp := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if comp == "" {
			continue
		}
		child, er := syscall.Openat(fd, comp, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if er != nil {
			return nil, er
		}
		fd = child
	}
	return os.NewFile(uintptr(fd), "shared-root"), nil
}

func relativeComponents(rel string) ([]string, error) {
	if rel == "" || len(rel) > 1024 || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\\\x00") {
		return nil, ErrDenied
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 64 {
		return nil, ErrDenied
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > 255 {
			return nil, ErrDenied
		}
	}
	return parts, nil
}

func openParent(root, rel string) (*os.File, string, error) {
	parts, err := relativeComponents(rel)
	if err != nil {
		return nil, "", err
	}
	dir, err := openDirectory(root)
	if err != nil {
		return nil, "", err
	}
	for _, p := range parts[:len(parts)-1] {
		fd, er := syscall.Openat(int(dir.Fd()), p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = dir.Close()
		if er != nil {
			return nil, "", er
		}
		dir = os.NewFile(uintptr(fd), "shared-subdir")
	}
	return dir, parts[len(parts)-1], nil
}

func Read(root, rel string) (string, error) {
	dir, base, err := openParent(root, rel)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), base, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "shared-read")
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Size > MaxFileBytes {
		return "", ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > MaxFileBytes {
		return "", ErrDenied
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Write uses a fresh, unguessable inode and renameat against the opened parent
// directory. It cannot follow the destination symlink or mutate hardlinked
// inodes. No mkdir, device writes, arbitrary absolute paths or host mounts.
func Write(root, rel, encoded string) error {
	if len(encoded) > base64.StdEncoding.EncodedLen(MaxFileBytes) {
		return ErrDenied
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) > MaxFileBytes {
		return ErrDenied
	}
	dir, base, err := openParent(root, rel)
	if err != nil {
		return err
	}
	defer dir.Close()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := ".nl-broker-" + hex.EncodeToString(random[:])
	fd, err := syscall.Openat(int(dir.Fd()), temp, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(int(dir.Fd()), temp)
	f := os.NewFile(uintptr(fd), "shared-write")
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(dir.Fd()), temp, int(dir.Fd()), base); err != nil {
		return err
	}
	return dir.Sync()
}
