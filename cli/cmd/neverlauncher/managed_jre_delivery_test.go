package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeManagedJREZipFixture0155(t *testing.T, path, entry, arch string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	w, err := zw.Create(entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(syntheticPE0152(t, arch, false)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeManagedJRETarFixture0155(t *testing.T, path, entry, platform, arch string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	var data []byte
	if platform == "linux" {
		data = fakeLinuxELF0153(arch, 0x55)
	} else {
		data = fakeSignedMachO0154(t, arch)
	}
	if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeManagedJREFixture0155(t *testing.T, dir, ver string) {
	t.Helper()
	var targets []ManagedJRETarget0155
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"x64", "arm64"} {
			name := managedJREArchiveName0155(ver, platform, arch)
			path := filepath.Join(dir, name)
			entry := "jdk/bin/java"
			format := "tar.gz"
			vendorOS := platform
			vendorArch := arch
			if platform == "windows" {
				entry = "jdk/bin/java.exe"
				format = "zip"
			}
			if platform == "macos" {
				entry = "jdk/Contents/Home/bin/java"
				vendorOS = "mac"
			}
			if arch == "arm64" {
				vendorArch = "aarch64"
			}
			if format == "zip" {
				writeManagedJREZipFixture0155(t, path, entry, arch)
			} else {
				writeManagedJRETarFixture0155(t, path, entry, platform, arch)
			}
			sum, size, err := hashFile(path)
			if err != nil {
				t.Fatal(err)
			}
			targets = append(targets, ManagedJRETarget0155{
				Platform: platform, Architecture: arch, Distribution: "temurin", MajorVersion: managedJREMajor0155,
				ReleaseName: "jdk-21.0.8+9", Semver: "21.0.8+9", Archive: name, Format: format,
				SHA256: sum, Size: size, JavaEntry: entry,
				SourceURL: "https://example.invalid/temurin/" + name, SourceSHA256: sum,
				VendorOS: vendorOS, VendorArch: vendorArch,
			})
		}
	}
	targets = sortedManagedJRETargets0155(targets)
	manifest := ManagedJREManifest0155{
		SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Distribution: "temurin",
		Vendor: "Eclipse Adoptium", MajorVersion: managedJREMajor0155, GeneratedAt: "2026-09-24T20:41:23Z", Targets: targets,
	}
	if err := writeJSONFile(filepath.Join(dir, managedJREManifestFile0155), manifest); err != nil {
		t.Fatal(err)
	}
	manifestHash, _, err := hashFile(filepath.Join(dir, managedJREManifestFile0155))
	if err != nil {
		t.Fatal(err)
	}
	evidence := ManagedJREEvidence0155{
		SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Distribution: "temurin", Vendor: "Eclipse Adoptium",
		IntegrityMode: "exact-vendor-archive-sha256", Manifest: managedJREManifestFile0155, ManifestSHA256: manifestHash, GeneratedAt: "2026-09-24T20:41:23Z",
	}
	for _, target := range targets {
		evidence.Targets = append(evidence.Targets, ManagedJREEvidenceTarget0155{
			Platform: target.Platform, Architecture: target.Architecture, Archive: target.Archive,
			SHA256: target.SHA256, Size: target.Size, SourceURL: target.SourceURL, SourceSHA256: target.SourceSHA256,
		})
	}
	if err := writeJSONFile(filepath.Join(dir, managedJREEvidenceFile0155), evidence); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
}

func TestManagedJREDistributionRequired0155(t *testing.T) {
	if managedJREDistributionRequired0155("0.15.4") {
		t.Fatal("0.15.4 must not require Managed JRE Distribution")
	}
	for _, ver := range []string{"0.15.5", "0.16.0", "1.0.0"} {
		if !managedJREDistributionRequired0155(ver) {
			t.Fatalf("%s must require Managed JRE Distribution", ver)
		}
	}
}

func TestManagedJREDistributionSixTargets0155(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.5"
	writeManagedJREFixture0155(t, dir, ver)
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
	if err := verifyManagedJREDistribution0155(dir, ver, true); err != nil {
		t.Fatal(err)
	}
}

func TestManagedJREDistributionRejectsTamper0155(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.5"
	writeManagedJREFixture0155(t, dir, ver)
	path := filepath.Join(dir, managedJREArchiveName0155(ver, "linux", "arm64"))
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := verifyManagedJREDistribution0155(dir, ver, true); err == nil {
		t.Fatal("tampered Managed JRE archive must fail closed")
	}
}
