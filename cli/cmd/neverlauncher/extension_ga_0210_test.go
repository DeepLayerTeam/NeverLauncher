package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtensionUpgradeSource0210(t *testing.T) {
	dir := t.TempDir()
	manifest := CanonicalExtensionManifest0201{SchemaVersion: "2.0", ID: "ru.test.ga", Name: "GA", Version: "1.2.3", Publisher: "Tests", API: "3.7", Targets: []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "backend/bin/extension"}}}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, canonicalExtensionManifestName0201), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "backend"), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := "module example.test/ext\n\ngo 1.22\n\nrequire gitflic.ru/skif4er/neverlauncher/sdk/backend/go v0.20.10\n"
	if err := os.WriteFile(filepath.Join(dir, "backend", "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extensionUpgradeSource0210([]string{dir}); err != nil {
		t.Fatal(err)
	}
	upgraded, _, _, err := loadCanonicalExtension0201(dir)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.API != "1.0" {
		t.Fatalf("api=%s", upgraded.API)
	}
	got, err := os.ReadFile(filepath.Join(dir, "backend", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "v0.21.0") {
		t.Fatalf("go.mod not upgraded: %s", got)
	}
}
func TestExtensionUpgradeSourceRejectsSignedPackage0210(t *testing.T) {
	if err := extensionUpgradeSource0210([]string{"example.nlext"}); err == nil {
		t.Fatal("expected immutable package error")
	}
}

func TestSupportsHostHello0210(t *testing.T) {
	for _, tc := range []struct {
		manifest string
		hello    string
		want     bool
	}{
		{"3.7", "", true},
		{"3.7", "3.7", true},
		{"3.7", "1.0", true},
		{"1.0", "1.0", true},
		{"1.0", "", false},
		{"2.0", "1.0", false},
	} {
		if got := supportsHostHello0210(tc.manifest, tc.hello); got != tc.want {
			t.Fatalf("supportsHostHello0210(%q,%q)=%v want %v", tc.manifest, tc.hello, got, tc.want)
		}
	}
}
