package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRollbackBoundSnapshot0448(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	data := []byte(`{"worldSha256":"` + strings.Repeat("a", 64) + `","loader":"forge","optionalPresetSha256":"` + strings.Repeat("b", 64) + `","players":[]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	obj, actual, err := rollbackReadSnapshot0448(path)
	if err != nil || obj == nil {
		t.Fatalf("read: %v", err)
	}
	sum := sha256.Sum256(data)
	if actual != hex.EncodeToString(sum[:]) {
		t.Fatal("rollback evidence digest must bind exact exported JSON bytes")
	}
	if err := os.WriteFile(path, append(data, []byte("\n{}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rollbackReadSnapshot0448(path); err == nil {
		t.Fatal("accepted trailing object")
	}
	if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rollbackReadSnapshot0448(path); err != nil {
		t.Fatal(err)
	} // API validates typed snapshot
	if err := os.Symlink(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	// Существующий код требует обычный файл по разрешённому пути, но не требует абсолютных путей для снимков.
	if _, _, err := rollbackReadSnapshot0448(filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
}
