package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A MirrorHelper cache repair is verified before replacing existing bytes.
// A bad download cannot overwrite a cached object even when it is corrupt.
func TestMirrorInstallerCacheRepair0427(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "cache", "installer.jar")
	source := filepath.Join(root, "source.jar")
	expected := []byte("signed and pinned installer contents")
	if err := os.WriteFile(source, expected, 0600); err != nil {
		t.Fatal(err)
	}
	art := mirrorArtifact0274{File: source, SHA256: mirrorSHA0274(expected)}
	if err := mirrorEnsureInstaller0427(context.Background(), dest, art); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(dest, art.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("tampered cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := mirrorEnsureInstaller0427(context.Background(), dest, art); err != nil {
		t.Fatal(err)
	}
	if _, err := mirrorCheckedHash0274(dest, art.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("original corrupted cache"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := art
	bad.SHA256 = strings.Repeat("0", 64)
	if err := mirrorEnsureInstaller0427(context.Background(), dest, bad); err == nil {
		t.Fatal("accepted bad replacement hash")
	}
	bytes, err := os.ReadFile(dest)
	if err != nil || string(bytes) != "original corrupted cache" {
		t.Fatalf("failed repair changed destination: %v", err)
	}
	// Exercise the actual CLI dispatcher and its pinned offline recovery path.
	if err := handleRuntimeMirror0274([]string{
		"repair-installer", "--cache-file", dest,
		"--source-file", source, "--sha256", art.SHA256,
		"--output", filepath.Join(root, "repair.json"),
	}); err != nil {
		t.Fatalf("CLI cache repair: %v", err)
	}
	if _, err := mirrorCheckedHash0274(dest, art.SHA256); err != nil {
		t.Fatalf("CLI did not restore verified bytes: %v", err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, dest); err == nil {
		if err := mirrorEnsureInstaller0427(context.Background(), dest, art); err == nil {
			t.Fatal("accepted symlink cache entry")
		}
	}
}
