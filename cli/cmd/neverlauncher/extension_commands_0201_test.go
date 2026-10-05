package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalExtensionManifestValidate0201(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, canonicalExtensionManifestName0201)
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0",
		ID:            "ru.example.extension",
		Name:          "Example",
		Version:       "1.0.0",
		Publisher:     "Example Publisher",
		API:           "3.7",
		Targets:       []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "bin/backend"}},
		Permissions:   []string{"release:read"},
	}
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	got, resolved, digest, err := loadCanonicalExtension0201(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path || got.ID != manifest.ID || len(digest) != 64 {
		t.Fatalf("unexpected canonical manifest result: %#v %s %s", got, resolved, digest)
	}
}

func TestImportLegacyPluginManifest0201(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "neverlauncher-plugin.json")
	legacy := PluginManifest{
		SchemaVersion: "1.2",
		ID:            "ru.example.legacy",
		Name:          "Legacy",
		Version:       "1.4.2",
		Target:        "admin",
		API:           "3.7",
		Entrypoint:    "index.ts",
		Permissions:   []string{"ui:extend"},
		Metadata:      map[string]string{"publisher": "Legacy Publisher", "custom": "value"},
	}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(legacyPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, source, err := importLegacyPluginManifest0201(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if source != legacyPath || manifest.SchemaVersion != "2.0" || manifest.Publisher != "Legacy Publisher" || len(manifest.Targets) != 1 || manifest.Targets[0].Kind != "admin" {
		t.Fatalf("legacy import mismatch: %#v source=%s", manifest, source)
	}
	if manifest.Metadata["importedFrom"] != "neverlauncher-plugin.json" || manifest.Metadata["custom"] != "value" {
		t.Fatalf("legacy metadata not preserved: %#v", manifest.Metadata)
	}
}
