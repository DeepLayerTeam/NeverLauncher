package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsProtectionGARequired0190(t *testing.T) {
	if windowsProtectionGARequired0190("0.18.12") || !windowsProtectionGARequired0190("0.19.0") || !windowsProtectionGARequired0190("1.0.0") {
		t.Fatal("Windows Protection GA version gate mismatch")
	}
	if windowsProtectionGAStableVersion0190("0.19.0") != nil {
		t.Fatal("stable 0.19.0 rejected")
	}
	if windowsProtectionGAStableVersion0190("0.19.0-rc.1") == nil {
		t.Fatal("prerelease accepted as Windows Protection GA")
	}
}

func TestWindowsProtectionGABoundaryBindsRCAndArtifacts0190(t *testing.T) {
	artifacts := []windowsProtectionArtifact01812{{Name: "neverguard.exe", Size: 17, SHA256: strings.Repeat("a", 64)}}
	caps := []string{"aggressive-protection-profile", "production-ga-user-mode-boundary"}
	first := windowsProtectionGABoundaryDigest0190("0.19.0", testSourceCommit01511, windowsProtectionRepository01812, strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), artifacts, caps)
	second := windowsProtectionGABoundaryDigest0190("0.19.0", testSourceCommit01511, windowsProtectionRepository01812, strings.Repeat("f", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), artifacts, caps)
	if first == second || len(first) != 64 {
		t.Fatal("Windows Protection GA boundary does not bind RC certificate")
	}
}

func TestWindowsProtectionGACapabilities0190(t *testing.T) {
	caps := expectedWindowsProtectionGACapabilities0190()
	required := map[string]bool{
		"continuous-attestation-v2":                             false,
		"production-ga-user-mode-boundary":                      false,
		"fail-closed-runtime-enforcement":                       false,
		"server-enforced-continuous-attestation-v2-join-ticket": false,
		"kernel-driver-free-production-package":                 false,
	}
	for _, cap := range caps {
		if _, ok := required[cap]; ok {
			required[cap] = true
		}
	}
	for cap, seen := range required {
		if !seen {
			t.Fatalf("missing Windows Protection GA capability %s", cap)
		}
	}
}

func writeGAPackage0190(t *testing.T, dir, ver, arch string, driver bool) {
	t.Helper()
	packageName, manifestName := expectedWindowsPackage0152(ver, arch)
	artifactName := "neverguard-sensor.dll"
	if driver {
		artifactName = "neverguard-driver.sys"
	}
	manifest := map[string]any{"artifacts": []map[string]string{{"name": artifactName, "component": "sensor"}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, packageName))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	entry, err := zw.Create(artifactName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionGARejectsKernelDriverPayload0190(t *testing.T) {
	dir := t.TempDir()
	for _, arch := range []string{"x64", "arm64"} {
		writeGAPackage0190(t, dir, "0.19.0", arch, false)
	}
	if err := verifyWindowsUserModeOnlyPackages0190(dir, "0.19.0"); err != nil {
		t.Fatalf("driver-free packages rejected: %v", err)
	}
	writeGAPackage0190(t, dir, "0.19.0", "x64", true)
	if err := verifyWindowsUserModeOnlyPackages0190(dir, "0.19.0"); err == nil {
		t.Fatal("kernel driver payload accepted by Windows Protection GA")
	}
}

func TestWindowsProtectionGAWiredIntoProductionGates0190(t *testing.T) {
	for _, gates := range [][]string{productionReleaseCandidateRequiredGates01511("0.19.0"), productionDeliveryReleaseRequiredGates0160("0.19.0")} {
		seen := false
		for _, gate := range gates {
			if gate == "windows-protection-ga-fail-closed-user-mode-boundary" {
				seen = true
				break
			}
		}
		if !seen {
			t.Fatal("Windows Protection GA missing from production gate set")
		}
	}
}
