package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeliveryTargetNormalization0151(t *testing.T) {
	cases := []struct {
		platform string
		arch     string
		wantP    string
		wantA    string
	}{
		{"linux", "amd64", "linux", "x64"},
		{"win32", "x86_64", "windows", "x64"},
		{"darwin", "aarch64", "macos", "arm64"},
		{"macos", "universal2", "macos", "universal"},
	}
	for _, tc := range cases {
		target, err := canonicalDeliveryTarget(tc.platform, tc.arch)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.platform, tc.arch, err)
		}
		if target.Platform != tc.wantP || target.Architecture != tc.wantA {
			t.Fatalf("%s/%s normalized to %+v", tc.platform, tc.arch, target)
		}
	}
	if _, err := canonicalDeliveryTarget("linux", "universal"); err == nil {
		t.Fatal("universal architecture must be macOS-only")
	}
	if _, err := canonicalDeliveryTarget("linux", "386"); err == nil {
		t.Fatal("unsupported 32-bit architecture must be rejected")
	}
}

func TestDeliveryManifestBuildVerifyAndResolve0151(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"neverlauncher-desktop-linux-amd64":              "linux launcher",
		"neverguard-linux-amd64":                         "linux guard",
		"neverlauncher-desktop-0.15.1-windows-arm64.exe": "windows arm launcher",
		"neverlauncher-desktop-macos-universal":          "mac universal launcher",
		"neverlauncher-paper-bridge-0.15.1.jar":          "paper bridge",
		"RELEASE_NOTES.txt":                              "notes",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeDeliveryManifest0151(dir, "0.15.1"); err != nil {
		t.Fatalf("write delivery manifest: %v", err)
	}
	if err := verifyDeliveryManifest0151(dir, "0.15.1"); err != nil {
		t.Fatalf("verify delivery manifest: %v", err)
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.PublishedTargets) != 3 {
		t.Fatalf("expected linux x64, windows arm64 and macOS universal targets, got %+v", manifest.PublishedTargets)
	}
	macArm, err := canonicalDeliveryTarget("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	matches := resolveDeliveryArtifacts0151(manifest, macArm, "desktop-launcher", "")
	if len(matches) != 1 || matches[0].Name != "neverlauncher-desktop-macos-universal" {
		t.Fatalf("macOS universal resolution failed: %+v", matches)
	}
	linux, _ := canonicalDeliveryTarget("linux", "amd64")
	matches = resolveDeliveryArtifacts0151(manifest, linux, "guard", "")
	if len(matches) != 1 || matches[0].Architecture != "x64" {
		t.Fatalf("linux x64 guard resolution failed: %+v", matches)
	}
}

func TestDeliveryManifestTamperFailsClosed0151(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "neverlauncher-cli-linux-amd64")
	if err := os.WriteFile(artifact, []byte("original"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, "0.15.1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeliveryManifest0151(dir, "0.15.1"); err == nil {
		t.Fatal("tampered delivery artifact must fail verification")
	}
}

func TestDeliveryManifestRequiredFrom0151(t *testing.T) {
	if deliveryManifestRequired0151("0.15.0") {
		t.Fatal("0.15.0 must not require delivery manifest")
	}
	for _, ver := range []string{"0.15.1", "0.15.2", "0.16.0", "1.0.0"} {
		if !deliveryManifestRequired0151(ver) {
			t.Fatalf("%s must require delivery manifest", ver)
		}
	}
}

func TestReleaseBuildEmbedsDeliveryManifest0151(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	for _, name := range releaseArtifacts("0.15.1") {
		switch name {
		case deliveryManifestFile0151, "SBOM.spdx.json", "PROVENANCE.json", "RELEASE_NOTES.txt":
			continue
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte("fixture "+name+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := buildReleaseBundle("0.15.1", out, root, "", "compatibility/targets.json", "", "device-trust/targets.json", "", "guard-ci/targets.json", "", ""); err != nil {
		t.Fatalf("release build 0.15.1: %v", err)
	}
	if err := verifyDeliveryManifest0151(out, "0.15.1"); err != nil {
		t.Fatalf("embedded delivery manifest: %v", err)
	}
	manifest, err := readDeliveryManifest0151(out)
	if err != nil {
		t.Fatal(err)
	}
	foundLinuxCLI := false
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == "neverlauncher-cli-linux-amd64" {
			foundLinuxCLI = artifact.Platform == "linux" && artifact.Architecture == "x64" && artifact.Component == "cli"
		}
	}
	if !foundLinuxCLI {
		t.Fatal("release delivery manifest does not contain canonical linux/x64 CLI metadata")
	}
}
