package sqlitedurable

// Mandatory, verified physical backup before a versioned SQLite migration.
// The caller retains the exclusive owner lock for the entire operation.
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
		return "", errors.New("invalid SQLite backup label")
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
		return "", fmt.Errorf("unsafe SQLite pre-upgrade directory %s", dir)
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, fmt.Sprintf("%s-%s-%d-%s.sqlite", filepath.Base(abs), label, time.Now().UTC().UnixNano(), token))
	if _, err = OnlineBackup(ctx, abs, dest); err != nil {
		return "", fmt.Errorf("mandatory SQLite upgrade backup: %w", err)
	}
	if _, err = VerifyBackup(ctx, dest); err != nil {
		return "", fmt.Errorf("SQLite upgrade backup verification: %w", err)
	}
	proof, err := os.MkdirTemp(dir, ".upgrade-proof-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(proof)
	if _, err = RestoreBackup(ctx, dest, filepath.Join(proof, "restored.sqlite"), false); err != nil {
		return "", fmt.Errorf("SQLite upgrade restore proof: %w", err)
	}
	return dest, nil
}
