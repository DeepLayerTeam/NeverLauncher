package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Use the same exclusive, private creation for temporary archive exports.
func createMigrationPrivateTemp(dir string) (*os.File, error) {
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		f, err := createMigrationPrivateFile(filepath.Join(dir, ".gravit-export-"+hex.EncodeToString(random[:])+".tmp"))
		if !os.IsExist(err) {
			return f, err
		}
	}
	return nil, os.ErrExist
}
