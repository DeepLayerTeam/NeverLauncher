package releasekeypaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OutsideBundle rejects both lexical containment and symlink aliases.
// A verification/signing trust anchor must be supplied independently of
// attacker-controlled bundle contents, even if the key path resolves elsewhere.
func OutsideBundle(bundle, key string) error {
	bundleAbs, err := filepath.Abs(bundle)
	if err != nil {
		return err
	}
	keyAbs, err := filepath.Abs(key)
	if err != nil {
		return err
	}
	// First reject a name *inside* the bundle, even when it links outside.
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
