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
			t.Fatalf("%s/%s нормализовано в %+v", tc.platform, tc.arch, target)
		}
	}
	if _, err := canonicalDeliveryTarget("linux", "universal"); err == nil {
		t.Fatal("Универсальная архитектура допустима только для macOS")
	}
	if _, err := canonicalDeliveryTarget("linux", "386"); err == nil {
		t.Fatal("Неподдерживаемая 32-битная архитектура должна отклоняться")
	}
}

func TestDeliveryManifestBuildVerifyAndResolve0151(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"launcher-desktop-linux-amd64":              "linux launcher",
		"guard-linux-amd64":                         "linux guard",
		"launcher-desktop-0.15.1-windows-arm64.exe": "windows arm launcher",
		"launcher-desktop-macos-universal":          "mac universal launcher",
		"launcher-paper-bridge-0.15.1.jar":          "paper bridge",
		"RELEASE_NOTES.txt":                              "notes",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeDeliveryManifest0151(dir, "0.15.1"); err != nil {
		t.Fatalf("Ошибка записи манифеста поставки: %v", err)
	}
	if err := verifyDeliveryManifest0151(dir, "0.15.1"); err != nil {
		t.Fatalf("Ошибка проверки манифеста поставки: %v", err)
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.PublishedTargets) != 3 {
		t.Fatalf("Ожидались Linux x64, Windows ARM64 и универсальная macOS; получено: %+v", manifest.PublishedTargets)
	}
	macArm, err := canonicalDeliveryTarget("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	matches := resolveDeliveryArtifacts0151(manifest, macArm, "desktop-launcher", "")
	if len(matches) != 1 || matches[0].Name != "launcher-desktop-macos-universal" {
		t.Fatalf("Не удалось определить универсальный пакет macOS: %+v", matches)
	}
	linux, _ := canonicalDeliveryTarget("linux", "amd64")
	matches = resolveDeliveryArtifacts0151(manifest, linux, "guard", "")
	if len(matches) != 1 || matches[0].Architecture != "x64" {
		t.Fatalf("Не удалось определить Guard для Linux x64: %+v", matches)
	}
}

func TestDeliveryManifestTamperFailsClosed0151(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "launcher-cli-linux-amd64")
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
		t.Fatal("Изменённый артефакт поставки должен отклоняться при проверке")
	}
}

func TestDeliveryManifestRequiredFrom0151(t *testing.T) {
	if deliveryManifestRequired0151("0.15.0") {
		t.Fatal("Версия 0.15.0 не должна требовать манифест поставки")
	}
	for _, ver := range []string{"0.15.1", "0.15.2", "0.16.0", "1.0.0"} {
		if !deliveryManifestRequired0151(ver) {
			t.Fatalf("%s должен требовать манифест поставки", ver)
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
		t.Fatalf("Ошибка релизной сборки 0.15.1: %v", err)
	}
	if err := verifyDeliveryManifest0151(out, "0.15.1"); err != nil {
		t.Fatalf("Встроенный манифест поставки: %v", err)
	}
	manifest, err := readDeliveryManifest0151(out)
	if err != nil {
		t.Fatal(err)
	}
	foundLinuxCLI := false
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == "launcher-cli-linux-amd64" {
			foundLinuxCLI = artifact.Platform == "linux" && artifact.Architecture == "x64" && artifact.Component == "cli"
		}
	}
	if !foundLinuxCLI {
		t.Fatal("В релизном манифесте поставки отсутствуют канонические метаданные CLI Linux x64")
	}
}

func TestDeliveryManifestClassifiesGuardSensor0182(t *testing.T) {
	name := "guard-sensor-windows-arm64.dll"
	if got := deliveryArtifactComponent(name); got != "sensor" {
		t.Fatalf("компонент датчика: %q", got)
	}
	target := deliveryArtifactTarget(name)
	if target.Platform != "windows" || target.Architecture != "arm64" {
		t.Fatalf("цель датчика: %+v", target)
	}
	if got := deliveryArtifactFormat(name); got != "dll" {
		t.Fatalf("формат датчика: %q", got)
	}
}
