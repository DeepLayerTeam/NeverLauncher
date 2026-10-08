//go:build !windows

package extensionlifecycle

import "os"

// syncDir0204 persists directory metadata after atomic rename on platforms
// where fsync on a directory descriptor is supported.
func syncDir0204(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
