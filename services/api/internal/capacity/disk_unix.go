//go:build linux || darwin || freebsd

package capacity

import (
	"os"
	"path/filepath"
	"syscall"
)

func measureDisk(name, path string) (Disk, error) {
	d := Disk{Name: name}
	dir, err := canonicalExistingDir(path)
	if err != nil {
		return d, err
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(dir, &fs); err != nil {
		return d, err
	}
	d.CapacityBytes = fs.Blocks * uint64(fs.Bsize)
	d.AvailableBytes = fs.Bavail * uint64(fs.Bsize)
	if d.CapacityBytes > 0 {
		d.AvailableFraction = float64(d.AvailableBytes) / float64(d.CapacityBytes)
	}
	if fi, e := os.Stat(path); e == nil && fi.Mode().IsRegular() {
		d.DataBytes = fi.Size()
	} else if e == nil && fi.IsDir() {
		_ = filepath.Base(path)
	}
	return d, nil
}
