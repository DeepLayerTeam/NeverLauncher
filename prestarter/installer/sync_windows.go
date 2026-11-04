//go:build windows

package installer

// Windows не предоставляет переносимый fsync каталогов для Go; перед атомарным Rename
// вызывается Sync файла. NTFS журналирует метаданные каталогов.
func syncParent(path string) error { return nil }
