//go:build !windows

package main

import (
	"fmt"
	"os"
)

func hostPrivateCheck(path string, info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("небезопасные права: %s", path)
	}
	return nil
}
func hostPrivateRestrictDir(path string) error { return os.Chmod(path, 0700) }
