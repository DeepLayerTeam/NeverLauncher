//go:build windows

package extensionlifecycle

// Windows не поддерживает Sync в стиле fsync для дескрипторов
// каталогов, открытых os.Open. Сам файл сбрасывается до Rename,
// а MoveFileEx/NTFS обеспечивает атомарное изменение метаданных.
// Считайте барьер надёжности каталога выполненным вместо
// ACCESS_DENIED после каждой успешной установки или удаления.
func syncDir0204(string) error { return nil }
