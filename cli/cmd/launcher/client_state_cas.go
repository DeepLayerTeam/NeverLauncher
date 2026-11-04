package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Returns a digest of the exact persisted version pointer, not a timestamp.
// A missing pointer has a distinct sentinel from an empty pointer.
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
		return "", errors.New("client state must be a regular file")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
