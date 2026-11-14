//go:build !windows

// Package privatefile provides fail-closed permission checks for sensitive files.
package privatefile

import "os"

// Check rejects permissions represented by forbidden on Unix.
func Check(_ string, info os.FileInfo, forbidden os.FileMode) bool {
	return info != nil && info.Mode().Perm()&forbidden == 0
}

// Restrict installs owner-only permissions, for newly created private fixtures.
func Restrict(path string, directory bool) error {
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
