package releasekeypaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OutsideBundle отклоняет и лексическую вложенность, и алиасы символьных ссылок. Корень доверия
// проверки или подписи нужно предоставлять независимо от содержимого пакета, контролируемого
// злоумышленником, даже если путь ключа разрешается наружу.
func OutsideBundle(bundle, key string) error {
	bundleAbs, err := filepath.Abs(bundle)
	if err != nil {
		return err
	}
	keyAbs, err := filepath.Abs(key)
	if err != nil {
		return err
	}
	// Сначала отклоните имя ВНУТРИ пакета, даже если ссылка ведёт наружу.
	if err = outside(bundleAbs, keyAbs); err != nil {
		return err
	}
	bundleReal, err := filepath.EvalSymlinks(bundleAbs)
	if err != nil {
		return fmt.Errorf("Не удалось определить пакет релиза: %w", err)
	}
	keyReal, err := filepath.EvalSymlinks(keyAbs)
	if err != nil {
		return fmt.Errorf("Не удалось определить доверенный ключ: %w", err)
	}
	info, err := os.Stat(keyReal)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("Требуется обычный файл: доверенный ключ")
	}
	return outside(bundleReal, keyReal)
}
func outside(bundle, key string) error {
	rel, err := filepath.Rel(bundle, key)
	if err != nil {
		return err
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("Ключ подписи и проверки релиза должен храниться вне пакета релиза")
	}
	return nil
}

// OutsideBundleState validates a persistent trust-state path, including its first creation.
func OutsideBundleState(bundle, state string) error {
	bundleAbs, err := filepath.Abs(bundle)
	if err != nil {
		return err
	}
	stateAbs, err := filepath.Abs(state)
	if err != nil {
		return err
	}
	if err = outside(bundleAbs, stateAbs); err != nil {
		return err
	}
	bundleReal, err := filepath.EvalSymlinks(bundleAbs)
	if err != nil {
		return err
	}
	parentReal, err := filepath.EvalSymlinks(filepath.Dir(stateAbs))
	if err != nil {
		return err
	}
	if err = outside(bundleReal, filepath.Join(parentReal, filepath.Base(stateAbs))); err != nil {
		return err
	}
	info, err := os.Lstat(stateAbs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("Trust state must be a regular file, not a symbolic link")
	}
	return OutsideBundle(bundle, stateAbs)
}
