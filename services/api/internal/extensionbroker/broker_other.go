//go:build !linux

package extensionbroker

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Общие файлы хоста намеренно отключены вне Linux: предварительная проверка пути
// не является границей безопасности против гонок с reparse points Windows.
func ParseRoots(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	var m map[string]string
	if e := json.Unmarshal([]byte(raw), &m); e != nil {
		return nil, e
	}
	if len(m) != 0 {
		return nil, errors.New("Для «shared filesystem broker» требуется «kernel-enforced, handle-relative file access on this platform»")
	}
	return map[string]string{}, nil
}
func Read(root, rel string) (string, error) { return "", ErrDenied }
func Write(root, rel, encoded string) error { return ErrDenied }

var _ = io.EOF
