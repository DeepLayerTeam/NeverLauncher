package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Возвращает дайджест точного сохранённого указателя версии, а не временную метку. У
// отсутствующего указателя отдельный маркер, отличный от пустого указателя.
func clientStateSHA2560228(root string) (string, error) {
	file := filepath.Join(root, ".launcher", "client-state.json")
	info, err := os.Lstat(file)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("client state: требуется обычный файл")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
