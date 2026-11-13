package installer

import (
	"path/filepath"
	"testing"
)

// On macOS /var and /tmp are symlink aliases; test the actual directory.
func resolvedTestTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
