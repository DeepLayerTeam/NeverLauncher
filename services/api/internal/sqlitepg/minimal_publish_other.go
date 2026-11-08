//go:build !linux

package sqlitepg

import "errors"

func publishNewDirectory0377(_, _ string) error {
	return errors.New("Для переноса минимального автономного пакета требуется атомарное переименование Linux без замены существующего файла")
}
