//go:build !windows

package installer

import (
	"os"
	"path/filepath"
)

func syncParent(path string) error {
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
