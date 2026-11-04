package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestUpdaterPreservesUserData0224(t *testing.T) {
	root := t.TempDir()
	src := t.TempDir()
	oldPath := filepath.Join(root, "old.json")
	newPath := filepath.Join(root, "new.json")
	write := func(base, p string, b []byte) {
		t.Helper()
		target := filepath.Join(base, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	keep := map[string][]byte{"saves/world/level.dat": []byte("world"), "screenshots/image.png": []byte("photo"), "resourcepacks/custom.zip": []byte("pack"), "options.txt": []byte("settings"), "config/mod.toml": []byte("settings"), "mods/my-own.jar": []byte("custom"), "mods/optional.jar": []byte("optional")}
	for p, b := range keep {
		write(root, p, b)
	}
	write(root, "mods/old.jar", []byte("obsolete"))
	content := []byte("published")
	write(src, "mods/new.jar", content)
	sum := sha256.Sum256(content)
	optDigest := sha256.Sum256([]byte("optional"))
	optionalFile := ManifestFile{Path: "mods/optional.jar", Size: int64(len("optional")), SHA256: hex.EncodeToString(optDigest[:]), Ownership: "optional"}
	old := Manifest{SchemaVersion: "2.0", ProjectID: "p", ProfileID: "profile", Version: "old", Files: []ManifestFile{
		{Path: "mods/old.jar", Required: true, Ownership: "required"},
		optionalFile,
		{Path: "config/mod.toml", Ownership: "user-owned"},
	}}
	newM := Manifest{SchemaVersion: "2.0", ProjectID: "p", ProfileID: "profile", Version: "new", Files: []ManifestFile{
		{Path: "mods/new.jar", Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), Required: true, Ownership: "required"},
		optionalFile,
		{Path: "config/mod.toml", Ownership: "user-owned"},
	}, FileRules: []FileRule0224{{Pattern: "mods/**", Action: "include", Ownership: "managed"}}}
	if err := writeJSONFile(oldPath, old); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(newPath, newM); err != nil {
		t.Fatal(err)
	}
	if _, err := applyManifestUpdate0156(oldPath, newPath, src, root); err != nil {
		t.Fatal(err)
	}
	for p, b := range keep {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil || string(got) != string(b) {
			t.Fatalf("data lost %s: %v %q", p, err, got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "mods/old.jar")); !os.IsNotExist(err) {
		t.Fatalf("managed obsolete file survived or unexpected error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "mods/new.jar"))
	if err != nil || string(got) != "published" {
		t.Fatalf("managed file not installed: %v %q", err, got)
	}
}

func TestFilePolicyRejectsOverwriteAndConflict0224(t *testing.T) {
	fixtures := []Manifest{
		{Files: []ManifestFile{{Path: "saves/a.dat", Required: true, Ownership: "required"}}},
		{Files: []ManifestFile{{Path: "mods/a.jar", Required: true, Ownership: "user-owned"}}},
		{Files: []ManifestFile{{Path: "mods/a.jar", Required: true}, {Path: "mods/A.jar", Required: true}}},
		{FileRules: []FileRule0224{{Pattern: "mods/**", Action: "include", Ownership: "managed"}, {Pattern: "mods/x/**", Action: "exclude", Ownership: "user-owned"}}},
	}
	for i, m := range fixtures {
		if err := validateManifestFilePolicy0224(m); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
