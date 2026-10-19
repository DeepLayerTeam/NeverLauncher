//go:build windows

package installer

// Windows does not expose a portable Go directory fsync; file Sync is
// performed before atomic Rename. NTFS journals directory metadata.
func syncParent(path string) error { return nil }
