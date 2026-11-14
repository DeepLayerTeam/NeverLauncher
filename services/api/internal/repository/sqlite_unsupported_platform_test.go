//go:build !linux

package repository

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteHTTPRejectsUncertifiedPlatform(t *testing.T) {
	repo, err := OpenSQLiteHTTPRepository0372(context.Background(), filepath.Join(t.TempDir(), "state.db"), "https://example.test")
	if repo != nil {
		repo.Close()
		t.Fatal("SQLite unexpectedly opened on an uncertified platform")
	}
	if err == nil {
		t.Fatal("SQLite must fail closed on an uncertified platform")
	}
}
