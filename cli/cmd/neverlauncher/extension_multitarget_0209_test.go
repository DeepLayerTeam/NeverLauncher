package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtensionPackageFourTargets0209(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX executable bits")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	root := t.TempDir()
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0",
		ID:            "ru.example.multitarget",
		Name:          "Multi Target",
		Version:       "1.0.0",
		Publisher:     "Example Publisher",
		API:           "3.7",
		Targets: []CanonicalExtensionTarget0201{
			{Kind: "backend", Entrypoint: "backend/extension"},
			{Kind: "admin", Entrypoint: "admin/index.html"},
			{Kind: "desktop", Entrypoint: "desktop/index.html"},
			{Kind: "cli", Entrypoint: "cli/bin/extension-cli"},
		},
		Permissions: []string{"desktop:contribute", "cli:contribute", "ui:contribute"},
		Admin:       &CanonicalExtensionAdminContributions0208{Pages: []CanonicalExtensionAdminPage0208{{ID: "main", Title: "Admin"}}},
		Desktop:     &CanonicalExtensionDesktopContributions0209{Pages: []CanonicalExtensionDesktopPage0209{{ID: "main", Title: "Desktop"}}},
		CLI:         &CanonicalExtensionCLIContributions0209{Namespace: "multi", Commands: []CanonicalExtensionCLICommand0209{{Name: "status", Description: "Status"}}},
	}
	if err := writeJSONFile(filepath.Join(root, canonicalExtensionManifestName0201), manifest); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		body string
		mode os.FileMode
	}{
		"backend/extension":     {"#!/bin/sh\nexit 0\n", 0o755},
		"admin/index.html":      {"<!doctype html><title>admin</title>", 0o644},
		"desktop/index.html":    {"<!doctype html><title>desktop</title>", 0o644},
		"cli/bin/extension-cli": {"#!/bin/sh\nexit 0\n", 0o755},
	}
	for rel, item := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(item.body), item.mode); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "multi.nlext")
	if _, err := packExtensionPackage0202(root, pkg); err != nil {
		t.Fatal(err)
	}
	analysis, err := analyzeExtensionPackage0202(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer analysis.Close()
	if len(analysis.Manifest.Targets) != 4 {
		t.Fatalf("targets=%#v", analysis.Manifest.Targets)
	}
	kinds := make([]string, 0, len(analysis.Manifest.Targets))
	for _, target := range analysis.Manifest.Targets {
		kinds = append(kinds, target.Kind)
	}
	joined := strings.Join(kinds, ",")
	for _, want := range []string{"admin", "backend", "cli", "desktop"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("target %s missing: %s", want, joined)
		}
	}
	if analysis.Manifest.Admin == nil || analysis.Manifest.Desktop == nil || analysis.Manifest.CLI == nil {
		t.Fatalf("multi-target contributions missing: %#v", analysis.Manifest)
	}
}

func TestSDKTemplatesDesktopAndCLI0209(t *testing.T) {
	desktop := sdkTemplate("desktop")
	if !strings.Contains(desktop, "neverextensions.desktop-rpc.v1") || !strings.Contains(desktop, "tauri.platform") || !strings.Contains(desktop, "parent.postMessage") {
		t.Fatalf("desktop scaffold is not a runnable sandbox client: %s", desktop)
	}
	cli := sdkTemplate("cli")
	for _, want := range []string{"NEVERLAUNCHER_EXTENSION_HOST_URL", "NEVERLAUNCHER_EXTENSION_HOST_TOKEN", "/v1/hello", "status"} {
		if !strings.Contains(cli, want) {
			t.Fatalf("CLI scaffold missing %q", want)
		}
	}
	if sdkEntrypoint("desktop") != "desktop/index.html" || sdkEntrypoint("cli") != "cli/bin/extension-cli" {
		t.Fatalf("unexpected SDK entrypoints")
	}
}
