package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func syntheticPE0152(t *testing.T, arch string, signed bool) []byte {
	t.Helper()
	_, machine, _, err := windowsTargetMetadata0152(arch)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0x300)
	data[0], data[1] = 'M', 'Z'
	peOffset := 0x80
	binary.LittleEndian.PutUint32(data[0x3c:0x40], uint32(peOffset))
	copy(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], machine)
	binary.LittleEndian.PutUint16(data[peOffset+20:peOffset+22], 240)
	optionalOffset := peOffset + 24
	binary.LittleEndian.PutUint16(data[optionalOffset:optionalOffset+2], 0x20b)
	if signed {
		securityEntry := optionalOffset + 112 + 4*8
		certOffset := 0x280
		certSize := 0x20
		binary.LittleEndian.PutUint32(data[securityEntry:securityEntry+4], uint32(certOffset))
		binary.LittleEndian.PutUint32(data[securityEntry+4:securityEntry+8], uint32(certSize))
		binary.LittleEndian.PutUint32(data[certOffset:certOffset+4], uint32(certSize))
		binary.LittleEndian.PutUint16(data[certOffset+4:certOffset+6], 0x0200)
		binary.LittleEndian.PutUint16(data[certOffset+6:certOffset+8], 0x0002)
		for i := certOffset + 8; i < certOffset+certSize; i++ {
			data[i] = byte(i)
		}
	}
	return data
}

func digestBytes0152(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeWindowsPackageFixture0152(t *testing.T, dir, ver, arch string, desktop, guard []byte, signed bool) WindowsSignedPackage0152 {
	t.Helper()
	packageName, rootManifestName := expectedWindowsPackage0152(ver, arch)
	manifest := map[string]any{
		"schemaVersion":             "1.1",
		"productVersion":            ver,
		"platform":                  "windows-" + arch,
		"architecture":              arch,
		"authenticodeRequired":      signed,
		"signingMode":               map[bool]string{true: "authenticode-rfc3161", false: "unsigned-development"}[signed],
		"neverGuardProtocolVersion": 4,
		"artifacts": []map[string]any{
			{"name": "neverlauncher-desktop-" + ver + "-windows-" + arch + ".exe", "component": "desktop-launcher", "architecture": arch, "sha256": digestBytes0152(desktop), "size": len(desktop)},
			{"name": "neverguard.exe", "component": "guard", "architecture": arch, "sha256": digestBytes0152(guard), "size": len(guard)},
		},
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := os.WriteFile(filepath.Join(dir, rootManifestName), manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(dir, packageName)
	zf, err := os.Create(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	for name, data := range map[string][]byte{
		"WINDOWS_PACKAGE_MANIFEST.json":                              manifestRaw,
		"neverlauncher-desktop-" + ver + "-windows-" + arch + ".exe": desktop,
		"neverguard.exe": guard,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}
	packageHash, packageSize, err := hashFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, _, err := hashFile(filepath.Join(dir, rootManifestName))
	if err != nil {
		t.Fatal(err)
	}
	return WindowsSignedPackage0152{Name: packageName, SHA256: packageHash, Size: packageSize, Manifest: rootManifestName, ManifestSHA256: manifestHash}
}

func buildWindowsEvidenceFixture0152(t *testing.T, dir, ver string, signed bool) WindowsSigningEvidence0152 {
	t.Helper()
	mode := "unsigned-development"
	var signer *WindowsSigner0152
	if signed {
		mode = "authenticode-rfc3161"
		now := time.Now().UTC()
		signer = &WindowsSigner0152{
			Subject: "CN=NeverLauncher Test", Issuer: "CN=Test CA", Thumbprint: "0123456789abcdef0123456789abcdef01234567",
			SerialNumber: "01", NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339),
		}
	}
	evidence := WindowsSigningEvidence0152{
		SchemaVersion: "1.0", Product: "NeverLauncher", ProductVersion: ver, Platform: "windows", SigningMode: mode,
		TimestampServer: "http://timestamp.test.invalid", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Signer: signer,
	}
	for _, arch := range []string{"x64", "arm64"} {
		rustTarget, _, machineText, _ := windowsTargetMetadata0152(arch)
		pe := syntheticPE0152(t, arch, signed)
		expected := expectedWindowsSignedArtifacts0152(arch)
		byComponent := map[string][]byte{}
		for component, name := range expected {
			payload := append([]byte(nil), pe...)
			payload = append(payload, []byte(component)...)
			// Appending data after the certificate table is legal for this parser fixture and keeps component hashes distinct.
			if err := os.WriteFile(filepath.Join(dir, name), payload, 0o755); err != nil {
				t.Fatal(err)
			}
			byComponent[component] = payload
		}
		pkg := writeWindowsPackageFixture0152(t, dir, ver, arch, byComponent["desktop-launcher"], byComponent["guard"], signed)
		target := WindowsSigningTarget0152{Architecture: arch, RustTarget: rustTarget, PEMachine: machineText, Package: pkg}
		for _, component := range []string{"cli", "desktop-launcher", "guard"} {
			name := expected[component]
			payload := byComponent[component]
			artifact := WindowsSignedArtifact0152{
				Name: name, Component: component, Architecture: arch, PEMachine: machineText,
				SHA256: digestBytes0152(payload), Size: int64(len(payload)), AuthenticodeStatus: "NotSigned",
			}
			if signed {
				artifact.AuthenticodeStatus = "Valid"
				artifact.Timestamped = true
				artifact.SigntoolVerified = true
				artifact.SignerThumbprint = signer.Thumbprint
				artifact.TimestampSignerThumbprint = "89abcdef0123456789abcdef0123456789abcdef"
			}
			target.Artifacts = append(target.Artifacts, artifact)
		}
		evidence.Targets = append(evidence.Targets, target)
	}
	pairs := []map[string]any{}
	for _, target := range evidence.Targets {
		byComponent := map[string]WindowsSignedArtifact0152{}
		for _, artifact := range target.Artifacts {
			byComponent[artifact.Component] = artifact
		}
		pairs = append(pairs, map[string]any{
			"guardSha256":         byComponent["guard"].SHA256,
			"launcherSha256":      byComponent["desktop-launcher"].SHA256,
			"requireAuthenticode": signed,
		})
	}
	allowlist := map[string]any{
		"schemaVersion": "2.0",
		"releases": map[string]any{ver: map[string]any{
			"protocolVersion": 4,
			"platforms": map[string]any{"windows": map[string]any{
				"signingMode": map[bool]string{true: "authenticode", false: "unsigned-development"}[signed],
				"artifacts":   pairs,
			}},
		}},
	}
	if err := writeJSONFile(filepath.Join(dir, windowsDeliveryAllowlistFile0152), allowlist); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestWindowsPEArchitectureAndCertificateTable0152(t *testing.T) {
	for _, arch := range []string{"x64", "arm64"} {
		unsigned, err := inspectWindowsPEBytes0152(syntheticPE0152(t, arch, false))
		if err != nil || unsigned.Architecture != arch || unsigned.HasSignature {
			t.Fatalf("unsigned %s PE inspection failed: %+v err=%v", arch, unsigned, err)
		}
		signed, err := inspectWindowsPEBytes0152(syntheticPE0152(t, arch, true))
		if err != nil || signed.Architecture != arch || !signed.HasSignature {
			t.Fatalf("signed %s PE inspection failed: %+v err=%v", arch, signed, err)
		}
	}
}

func TestWindowsSigningEvidenceCandidateAndPublishGate0152(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.2"
	evidence := buildWindowsEvidenceFixture0152(t, dir, ver, false)
	if err := writeJSONFile(filepath.Join(dir, windowsSigningEvidenceFile0152), evidence); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, false); err != nil {
		t.Fatalf("unsigned CI candidate should verify structurally: %v", err)
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, true); err == nil {
		t.Fatal("publish gate must reject unsigned Windows x64+ARM64 evidence")
	}
}

func TestWindowsSigningEvidenceTamperFailsClosed0152(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.2"
	evidence := buildWindowsEvidenceFixture0152(t, dir, ver, false)
	if err := writeJSONFile(filepath.Join(dir, windowsSigningEvidenceFile0152), evidence); err != nil {
		t.Fatal(err)
	}
	if err := writeDeliveryManifest0151(dir, ver); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "neverguard-windows-arm64.exe")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("tamper"))
	_ = f.Close()
	if err := verifyWindowsSigningEvidence0152(dir, ver, false); err == nil {
		t.Fatal("tampered Windows artifact must fail evidence verification")
	}
}

func TestWindowsSigningRequiredFrom0152(t *testing.T) {
	if windowsSigningRequired0152("0.15.1") {
		t.Fatal("0.15.1 must not require Windows dual-arch signing evidence")
	}
	for _, ver := range []string{"0.15.2", "0.15.3", "0.16.0", "1.0.0"} {
		if !windowsSigningRequired0152(ver) {
			t.Fatalf("%s must require Windows dual-arch signing evidence", ver)
		}
	}
}
