package macossandbox

import (
	"errors"
	"path/filepath"
	"strings"
)

// ValidateGrants rejects anything that cannot be brokered without granting
// additional App Sandbox entitlements to the extension process.
func ValidateGrants(read, write, network, secrets []string) error {
	for _, v := range read {
		if v != "package" && !sharedGrant(v) {
			return errors.New("macos-sandbox-invalid-read-grant")
		}
	}
	for _, v := range write {
		if v != "scratch" && !sharedGrant(v) {
			return errors.New("macos-sandbox-invalid-write-grant")
		}
	}
	for _, v := range network {
		if strings.ContainsAny(v, "/\\@?#") || len(v) > 253 || !strings.Contains(v, ":") {
			return errors.New("macos-sandbox-invalid-network-grant")
		}
	}
	for _, v := range secrets {
		if len(v) < 1 || len(v) > 128 || strings.ContainsAny(v, "/\\\x00\n\r") {
			return errors.New("macos-sandbox-invalid-secret-grant")
		}
	}
	return nil
}
func sharedGrant(v string) bool {
	if !strings.HasPrefix(v, "shared:") || len(v) > 96 || len(v) <= 7 {
		return false
	}
	for _, c := range v[7:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func IsInside(root, entry string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(entry) {
		return false
	}
	rel, err := filepath.Rel(root, entry)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
