package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func migrationFilePrivateForTest(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && hostPrivateCheck(path, info) == nil && (runtime.GOOS == "windows" || info.Mode().Perm() == 0600)
}

func TestMigrationPrivateExclusiveCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	f, err := createMigrationPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("private-test"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !migrationFilePrivateForTest(path, info) {
		t.Fatalf("private file: %v %v", info, err)
	}
	if f, err = createMigrationPrivateFile(path); !os.IsExist(err) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("exclusive create: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "private-test" {
		t.Fatalf("original changed: %v", err)
	}
}
