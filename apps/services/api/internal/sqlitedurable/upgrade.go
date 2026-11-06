package sqlitedurable

// Обязательная проверенная физическая резервная копия перед версионированной миграцией SQLite.
// Вызывающий код удерживает эксклюзивную блокировку владельца на всём протяжении операции.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func PreUpgradeBackup0472(ctx context.Context, source, label string) (string, error) {
	if label == "" || strings.ContainsAny(label, `/\\.\x00\r\n`) {
		return "", errors.New("Некорректное значение: «метка резервной копии SQLite»")
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(abs), "pre-upgrade-backups")
	if err = os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
		return "", fmt.Errorf("Небезопасное значение: «каталог перед обновлением SQLite» %s", dir)
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, fmt.Sprintf("%s-%s-%d-%s.sqlite", filepath.Base(abs), label, time.Now().UTC().UnixNano(), token))
	if _, err = OnlineBackup(ctx, abs, dest); err != nil {
		return "", fmt.Errorf("Обязательная резервная копия перед обновлением SQLite: %w", err)
	}
	if _, err = VerifyBackup(ctx, dest); err != nil {
		return "", fmt.Errorf("Проверка резервной копии обновления SQLite: %w", err)
	}
	proof, err := os.MkdirTemp(dir, ".upgrade-proof-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(proof)
	if _, err = RestoreBackup(ctx, dest, filepath.Join(proof, "restored.sqlite"), false); err != nil {
		return "", fmt.Errorf("Подтверждение восстановления после обновления SQLite: %w", err)
	}
	return dest, nil
}
