//go:build windows

package extensionlifecycle

// Windows does not permit fsync-style Sync on directory handles opened by
// os.Open. The file itself is flushed before Rename, and MoveFileEx/NTFS
// provides the atomic metadata transition used by this lifecycle. Treat the
// directory durability barrier as already satisfied instead of turning every
// successful install/uninstall into ACCESS_DENIED.
func syncDir0204(string) error { return nil }
