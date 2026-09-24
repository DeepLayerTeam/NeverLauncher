package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func fakeLinuxELF0153(arch string, marker byte) []byte {
	data := make([]byte, 96)
	copy(data[:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4] = 2
	data[5] = 1
	data[6] = 1
	binary.LittleEndian.PutUint16(data[16:18], 3)
	machine, _, _ := linuxTargetMetadata0153(arch)
	binary.LittleEndian.PutUint16(data[18:20], machine)
	data[64] = marker
	return data
}

func shaHex0153(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeLinuxTargetFixture0153(t *testing.T, dir, ver, arch string) {
	t.Helper()
	_, machineText, err := linuxTargetMetadata0153(arch)
	if err != nil {
		t.Fatal(err)
	}
	packagePaths := map[string]string{
		"cli":              "neverlauncher/neverlauncher-cli",
		"api":              "neverlauncher/neverlauncher-api",
		"desktop-launcher": "neverlauncher/neverlauncher-desktop",
		"guard":            "neverlauncher/neverguard",
		"runtime":          "neverlauncher/neverruntime",
	}
	components := make([]string, 0, len(packagePaths))
	for component := range packagePaths {
		components = append(components, component)
	}
	sort.Strings(components)
	artifacts := make([]LinuxPackageArtifact0153, 0, len(components))
	payloads := map[string][]byte{}
	expectedNames := expectedLinuxArtifacts0153(arch)
	for i, component := range components {
		data := fakeLinuxELF0153(arch, byte(i+1))
		name := expectedNames[component]
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		packagePath := packagePaths[component]
		payloads[packagePath] = data
		artifacts = append(artifacts, LinuxPackageArtifact0153{
			Name: name, PackagePath: packagePath, Component: component, Architecture: arch,
			ELFMachine: machineText, SHA256: shaHex0153(data), Size: int64(len(data)), Mode: "0755",
		})
	}
	packageName, manifestName := expectedLinuxPackage0153(ver, arch)
	manifest := LinuxPackageManifest0153{
		SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Platform: "linux",
		Architecture: arch, ELFMachine: machineText, PackageFormat: "tar.gz", PackageArtifact: packageName, Artifacts: artifacts,
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := os.WriteFile(filepath.Join(dir, manifestName), manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := os.Create(filepath.Join(dir, packageName))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	paths := make([]string, 0, len(payloads))
	for path := range payloads {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		data := payloads[path]
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "neverlauncher/LINUX_PACKAGE_MANIFEST.json", Mode: 0o644, Size: int64(len(manifestRaw)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifestRaw); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func prepareLinuxBundleFixture0153(t *testing.T, ver string) string {
	t.Helper()
	dir := t.TempDir()
	writeLinuxTargetFixture0153(t, dir, ver, "x64")
	writeLinuxTargetFixture0153(t, dir, ver, "arm64")
	if err := writeLinuxProductionEvidence0153(dir, ver); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatalf("write delivery manifest: %v", err)
	}
	return dir
}

func TestLinuxProductionEvidence0153VerifiesBothArchitectures(t *testing.T) {
	ver := "0.15.3"
	dir := prepareLinuxBundleFixture0153(t, ver)
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		t.Fatalf("delivery verify: %v", err)
	}
	if err := verifyLinuxProductionEvidence0153(dir, ver, true); err != nil {
		t.Fatalf("linux production verify: %v", err)
	}
	manifest, err := readDeliveryManifest0151(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, target := range manifest.PublishedTargets {
		seen[target.Platform+"/"+target.Architecture] = true
	}
	if !seen["linux/x64"] || !seen["linux/arm64"] {
		t.Fatalf("delivery targets missing Linux x64/arm64: %#v", manifest.PublishedTargets)
	}
}

func TestLinuxProductionEvidence0153RejectsTamperedArtifact(t *testing.T) {
	ver := "0.15.3"
	dir := prepareLinuxBundleFixture0153(t, ver)
	path := filepath.Join(dir, "neverguard-linux-arm64")
	if err := os.WriteFile(path, fakeLinuxELF0153("arm64", 99), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyLinuxProductionEvidence0153(dir, ver, true); err == nil {
		t.Fatal("tampered Linux artifact must be rejected")
	}
}

func TestLinuxProductionEvidence0153RejectsWrongELFArchitecture(t *testing.T) {
	ver := "0.15.3"
	dir := t.TempDir()
	writeLinuxTargetFixture0153(t, dir, ver, "x64")
	writeLinuxTargetFixture0153(t, dir, ver, "arm64")
	if err := os.WriteFile(filepath.Join(dir, "neverlauncher-cli-linux-arm64"), fakeLinuxELF0153("x64", 1), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeLinuxProductionEvidence0153(dir, ver); err == nil {
		t.Fatal("wrong ARM64 ELF machine must be rejected")
	}
}

func TestLinuxProductionRequired0153VersionBoundary(t *testing.T) {
	if linuxProductionRequired0153("0.15.2") {
		t.Fatal("0.15.2 must not require Linux dual-arch production packages")
	}
	for _, ver := range []string{"0.15.3", "0.16.0", "1.0.0"} {
		if !linuxProductionRequired0153(ver) {
			t.Fatalf("%s must require Linux dual-arch production packages", ver)
		}
	}
}
