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
		return fmt.Errorf("resolve release bundle: %w", err)
	}
	keyReal, err := filepath.EvalSymlinks(keyAbs)
	if err != nil {
		return fmt.Errorf("resolve trusted key: %w", err)
	}
	info, err := os.Stat(keyReal)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("trusted key must be a regular file")
	}
	return outside(bundleReal, keyReal)
}
func outside(bundle, key string) error {
	rel, err := filepath.Rel(bundle, key)
	if err != nil {
		return err
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("release signing/verification key must be outside release bundle")
	}
	return nil
}
