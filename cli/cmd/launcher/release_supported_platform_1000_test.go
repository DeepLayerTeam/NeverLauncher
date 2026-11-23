package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic bytes exercise the release verifier; these are not GA installers.
func supportedPlatformFixture1000(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	commit := strings.Repeat("a", 40)
	doc := supportedPlatformGAReport1000{
		Schema:                    "launcher.supported-platform-ga/1.0.0",
		Version:                   "1.0.0",
		Commit:                    commit,
		Project:                   "test-project",
		SourceIndexSHA256:         strings.Repeat("b", 64),
		IndependentApprovalSHA256: strings.Repeat("c", 64),
		Status:                    "independently-approved-exact-native-packages",
		SupportedTargets:          []string{"windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64"},
		Packages:                  map[string]supportedPlatformGAFile1000{},
	}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			suffix := ".pkg"
			if platform == "windows" {
				suffix = ".exe"
			} else if platform == "linux" {
				suffix = ".deb"
			}
			name := "launcher-1.0.0-test-project-" + platform + "-" + arch + suffix
			names := []string{name}
			if platform == "linux" {
				names = append(names, name+".asc")
			}
			for _, filename := range names {
				data := []byte(strings.Repeat("real-byte-integrity-fixture:"+filename, 40))
				if err := os.WriteFile(filepath.Join(dir, filename), data, 0600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				doc.Packages[filename] = supportedPlatformGAFile1000{SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))}
			}
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, supportedPlatformGAReceipt1000), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, commit
}

func TestSupportedPlatformGA1000ExactBytes(t *testing.T) {
	dir, commit := supportedPlatformFixture1000(t)
	files, err := verifySupportedPlatformGA1000(dir, "1.0.0", commit)
	if err != nil || len(files) != 9 {
		t.Fatalf("want 8 native files plus required receipt, got %v: %v", files, err)
	}
	if _, err = verifySupportedPlatformGA1000(dir, "1.0.0", strings.Repeat("d", 40)); err == nil {
		t.Fatal("different source commit accepted")
	}
	if _, err = verifySupportedPlatformGA1000(dir, "1.1.0", commit); err == nil {
		t.Fatal("unreviewed future release accepted")
	}
}

func TestSupportedPlatformGA1000RejectsMutationAndLinks(t *testing.T) {
	dir, commit := supportedPlatformFixture1000(t)
	file := filepath.Join(dir, "launcher-1.0.0-test-project-linux-arm64.deb")
	if err := os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySupportedPlatformGA1000(dir, "1.0.0", commit); err == nil {
		t.Fatal("tampered native bytes accepted")
	}
	os.Remove(file)
	if err := os.Symlink(filepath.Join(dir, "SUPPORTED_PLATFORM_GA_1000.json"), file); err == nil {
		if _, err := verifySupportedPlatformGA1000(dir, "1.0.0", commit); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestSupportedPlatformGA1000RejectsMissingReceipt(t *testing.T) {
	dir, commit := supportedPlatformFixture1000(t)
	if err := os.Remove(filepath.Join(dir, supportedPlatformGAReceipt1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySupportedPlatformGA1000(dir, "1.0.0", commit); err == nil {
		t.Fatal("missing receipt accepted")
	}
}
