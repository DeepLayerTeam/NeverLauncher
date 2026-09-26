package main

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fakeSignedMachO0154(t *testing.T, arch string) []byte {
	t.Helper()
	_, cpu, _, err := macOSTargetMetadata0154(arch)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	copy(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe})
	binary.LittleEndian.PutUint32(data[4:8], cpu)
	binary.LittleEndian.PutUint32(data[12:16], 2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(data[16:20], 1) // ncmds
	binary.LittleEndian.PutUint32(data[20:24], 16)
	binary.LittleEndian.PutUint32(data[32:36], 0x1d) // LC_CODE_SIGNATURE
	binary.LittleEndian.PutUint32(data[36:40], 16)
	binary.LittleEndian.PutUint32(data[40:44], 64)
	binary.LittleEndian.PutUint32(data[44:48], 32)
	copy(data[64:96], []byte("FAKE-CMS-SIGNATURE-BYTES-0154!!"))
	return data
}

func writeMacOSFixture0154(t *testing.T, dir, ver, signingMode, teamID string, notarized bool) {
	t.Helper()
	var targets []MacOSNotarizationTarget0154
	var allow []map[string]any
	for _, arch := range []string{"x64", "arm64"} {
		rustTarget, _, cpuText, err := macOSTargetMetadata0154(arch)
		if err != nil {
			t.Fatal(err)
		}
		components := []struct{ component, name, bundle string }{
			{"cli", "neverlauncher-cli-macos-" + arch, "NeverLauncher.app/Contents/MacOS/neverlauncher-cli"},
			{"desktop-launcher", "neverlauncher-desktop-macos-" + arch, "NeverLauncher.app/Contents/MacOS/neverlauncher-desktop"},
			{"guard", "neverguard-macos-" + arch, "NeverLauncher.app/Contents/MacOS/neverguard"},
			{"runtime", "neverruntime-macos-" + arch, "NeverLauncher.app/Contents/MacOS/neverruntime"},
		}
		var artifacts []MacOSPackageArtifact0154
		payloadByPath := map[string][]byte{}
		for _, row := range components {
			data := fakeSignedMachO0154(t, arch)
			path := filepath.Join(dir, row.name)
			if err := os.WriteFile(path, data, 0o755); err != nil {
				t.Fatal(err)
			}
			sum, size, err := hashFile(path)
			if err != nil {
				t.Fatal(err)
			}
			artifact := MacOSPackageArtifact0154{Name: row.name, BundlePath: row.bundle, Component: row.component, Architecture: arch, CPUType: cpuText, SHA256: sum, Size: size, CodeSigned: true, HardenedRuntime: true, TeamID: teamID}
			artifacts = append(artifacts, artifact)
			payloadByPath[row.bundle] = data
		}
		pkgName, manifestName := expectedMacOSPackage0154(ver, arch)
		manifest := MacOSPackageManifest0154{SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Platform: "macos", Architecture: arch, CPUType: cpuText, RustTarget: rustTarget, PackageFormat: "zip", PackageArtifact: pkgName, BundleIdentifier: "ru.skif4er.neverlauncher", MinimumSystemVersion: "12.0", HashBindingMode: "final-artifact-sha256", Artifacts: artifacts}
		embeddedManifest := manifest
		embeddedManifest.HashBindingMode = "codesign+external-release-policy"
		embeddedManifest.Artifacts = append([]MacOSPackageArtifact0154(nil), artifacts...)
		if componentTransactionalUpdateRequired0157(ver) {
			for i := range embeddedManifest.Artifacts {
				if embeddedManifest.Artifacts[i].Component == "desktop-launcher" {
					preSign := append(append([]byte(nil), payloadByPath[embeddedManifest.Artifacts[i].BundlePath]...), []byte("-pre-outer-codesign")...)
					embeddedManifest.Artifacts[i].SHA256, embeddedManifest.Artifacts[i].Size = hashBytes0154(preSign)
				}
			}
		}
		manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		manifestRaw = append(manifestRaw, '\n')
		if err := os.WriteFile(filepath.Join(dir, manifestName), manifestRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		manifestHash, _, err := hashFile(filepath.Join(dir, manifestName))
		if err != nil {
			t.Fatal(err)
		}
		zf, err := os.Create(filepath.Join(dir, pkgName))
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(zf)
		for name, data := range payloadByPath {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		embeddedRaw, err := json.MarshalIndent(embeddedManifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		embeddedRaw = append(embeddedRaw, '\n')
		w, err := zw.Create("NeverLauncher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(embeddedRaw); err != nil {
			t.Fatal(err)
		}
		if componentTransactionalUpdateRequired0157(ver) {
			byComponent := map[string]MacOSPackageArtifact0154{}
			for _, artifact := range embeddedManifest.Artifacts {
				byComponent[artifact.Component] = artifact
			}
			update := componentUpdateManifest0157{
				SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Platform: "macos", Architecture: arch,
				Layout: "macos-app-bundle", TrustMode: signingMode, BundleName: "NeverLauncher.app",
			}
			for _, row := range []struct{ public, source, path string }{
				{"desktop", "desktop-launcher", "Contents/MacOS/neverlauncher-desktop"},
				{"guard", "guard", "Contents/MacOS/neverguard"},
				{"runtime", "runtime", "Contents/MacOS/neverruntime"},
			} {
				artifact := byComponent[row.source]
				update.Components = append(update.Components, componentUpdateArtifact0157{Component: row.public, SourcePath: row.path, TargetPath: row.path, SHA256: artifact.SHA256, Size: artifact.Size, Executable: true})
			}
			updateRaw, err := json.MarshalIndent(update, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			uw, err := zw.Create("NeverLauncher.app/Contents/Resources/" + componentUpdateManifestFile0157)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := uw.Write(append(updateRaw, '\n')); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := zf.Close(); err != nil {
			t.Fatal(err)
		}
		pkgHash, pkgSize, err := hashFile(filepath.Join(dir, pkgName))
		if err != nil {
			t.Fatal(err)
		}
		pkg := MacOSNotarizedPackage0154{Name: pkgName, SHA256: pkgHash, Size: pkgSize, Manifest: manifestName, ManifestSHA256: manifestHash, NotaryStatus: "not-requested", BundleCodeSignVerified: true}
		if notarized {
			pkg.NotarySubmissionID = map[string]string{"x64": "123e4567-e89b-42d3-a456-426614174000", "arm64": "223e4567-e89b-42d3-a456-426614174001"}[arch]
			pkg.NotaryStatus = "Accepted"
			pkg.Stapled = true
			pkg.StaplerValidated = true
			pkg.GatekeeperAccepted = true
		}
		targets = append(targets, MacOSNotarizationTarget0154{Architecture: arch, CPUType: cpuText, RustTarget: rustTarget, Package: pkg, Artifacts: artifacts})
		var guard, launcher string
		for _, a := range artifacts {
			if a.Component == "guard" {
				guard = a.SHA256
			}
			if a.Component == "desktop-launcher" {
				launcher = a.SHA256
			}
		}
		allow = append(allow, map[string]any{"architecture": arch, "guardSha256": guard, "launcherSha256": launcher, "notarized": notarized})
	}
	evidence := MacOSNotarizationEvidence0154{SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Platform: "macos", SigningMode: signingMode, TeamID: teamID, GeneratedAt: "2026-09-24T19:33:35Z", Targets: targets}
	if err := writeJSONFile(filepath.Join(dir, macOSNotarizationEvidenceFile0154), evidence); err != nil {
		t.Fatal(err)
	}
	allowlist := map[string]any{"schemaVersion": "3.0", "releases": map[string]any{ver: map[string]any{"protocolVersion": 4, "platforms": map[string]any{"macos": map[string]any{"signingMode": signingMode, "artifacts": allow}}}}}
	if err := writeJSONFile(filepath.Join(dir, macOSDeliveryAllowlistFile0154), allowlist); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
}

func TestMacOSProductionRequired0154(t *testing.T) {
	if macOSProductionRequired0154("0.15.3") {
		t.Fatal("0.15.3 must not require macOS x64+ARM64 notarization")
	}
	for _, ver := range []string{"0.15.4", "0.16.0", "1.0.0"} {
		if !macOSProductionRequired0154(ver) {
			t.Fatalf("%s must require macOS x64+ARM64 notarization", ver)
		}
	}
}

func TestInspectMacOSMachO0154(t *testing.T) {
	for _, arch := range []string{"x64", "arm64"} {
		info, err := inspectMacOSMachOBytes0154(fakeSignedMachO0154(t, arch))
		if err != nil {
			t.Fatal(err)
		}
		if info.Architecture != arch || !info.HasCodeSignature {
			t.Fatalf("unexpected Mach-O info: %+v", info)
		}
	}
	bad := fakeSignedMachO0154(t, "x64")
	binary.LittleEndian.PutUint32(bad[40:44], 4096)
	if _, err := inspectMacOSMachOBytes0154(bad); err == nil {
		t.Fatal("out-of-bounds LC_CODE_SIGNATURE must fail")
	}
}

func TestMacOSProductionEvidenceAdhocAndNotarized0154(t *testing.T) {
	for _, tc := range []struct {
		name, mode, team      string
		notarized, production bool
	}{
		{"adhoc", "adhoc-development", "ADHOC-CI", false, false},
		{"production", "developer-id-notarized", "ABCDE12345", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ver := "0.15.4"
			writeMacOSFixture0154(t, dir, ver, tc.mode, tc.team, tc.notarized)
			if err := verifyDeliveryManifest0151(dir, ver); err != nil {
				t.Fatal(err)
			}
			if err := verifyMacOSNotarizationEvidence0154(dir, ver, tc.production); err != nil {
				t.Fatal(err)
			}
			if !tc.production {
				if err := verifyMacOSNotarizationEvidence0154(dir, ver, true); err == nil {
					t.Fatal("publish verification must reject ad-hoc macOS evidence")
				}
			}
		})
	}
}

func TestMacOSProductionEvidenceDualManifestBinding0161(t *testing.T) {
	dir := t.TempDir()
	ver := "0.16.1"
	writeMacOSFixture0154(t, dir, ver, "adhoc-development", "ADHOC-CI", false)
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
	if err := verifyMacOSNotarizationEvidence0154(dir, ver, false); err != nil {
		t.Fatal(err)
	}
}

func TestMacOSProductionEvidenceRejectsTamper0154(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.4"
	writeMacOSFixture0154(t, dir, ver, "developer-id-notarized", "ABCDE12345", true)
	path := filepath.Join(dir, "neverguard-macos-arm64")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := verifyMacOSNotarizationEvidence0154(dir, ver, true); err == nil {
		t.Fatal("tampered macOS artifact must fail verification")
	}
}
