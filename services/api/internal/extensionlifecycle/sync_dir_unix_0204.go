//go:build !windows

package extensionlifecycle

import "os"

// syncDir0204 сохраняет метаданные каталога после атомарного
// переименования там, где поддерживается fsync дескриптора каталога.
func syncDir0204(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
