package sqlitecoord

import (
	"os"
	"testing"
)

// Test fixtures must obey the same private-directory contract as production.
func privateSQLiteTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
