package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func guardChecks0139(osName string) []string {
	checks := []string{
		"rustFormat", "guardUnitTests", "guardIntegrationTest", "clippy", "releaseBuild",
		"packageManifestVerified", "artifactHashesVerified", "authenticatedIpcV4",
		"runtimePolicyEnforced", "releasePackageBuilt", "guardRelease0139",
	}
	checks = append(checks, map[string]string{"linux": "linuxProductionGate", "windows": "windowsProductionGate", "macos": "macosProductionGate"}[osName])
	return checks
}

func writeGuardCIEvidenceFixture(t *testing.T, dir, out, ver, commit string) (string, string) {
	t.Helper()
	targets := releaseGuardCITargets{SchemaVersion: "1.0", ProductVersion: ver, Targets: []releaseGuardCITarget{
		{ID: "guard-linux-amd64", Runner: "ubuntu-24.04", OS: "linux", Arch: "x86_64", Required: true, CISigningMode: "none-linux-integrity", RequiredChecks: guardChecks0139("linux")},
		{ID: "guard-windows-amd64", Runner: "windows-2022", OS: "windows", Arch: "x86_64", Required: true, CISigningMode: "unsigned-development-ci", RequiredChecks: guardChecks0139("windows")},
		{ID: "guard-macos-universal", Runner: "macos-14", OS: "macos", Arch: "universal", Required: true, CISigningMode: "adhoc-ci", RequiredChecks: guardChecks0139("macos")},
	}}
	targetsRaw, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw = append(targetsRaw, '\n')
	targetsPath := filepath.Join(dir, "guard-ci-targets.json")
	if err := os.WriteFile(targetsPath, targetsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	mkChecks := func(names []string) map[string]bool {
		m := map[string]bool{}
		for _, name := range names {
			m[name] = true
		}
		return m
	}
	results := []releaseGuardCIResult{}
	for _, target := range targets.Targets {
		names := expectedGuardArtifactNames0139(target.OS, ver)
		artifacts := map[string]releaseGuardCIArtifact{}
		for _, role := range []string{"package", "launcher", "guard", "manifest", "allowlist"} {
			name := names[role]
			path := filepath.Join(out, name)
			if err := os.WriteFile(path, []byte(target.ID+"/"+role+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			digest, size, err := hashFile(path)
			if err != nil {
				t.Fatal(err)
			}
			artifacts[role] = releaseGuardCIArtifact{Name: name, Size: size, SHA256: digest}
		}
		results = append(results, releaseGuardCIResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: target.ID, Runner: target.Runner,
			OS: target.OS, Arch: target.Arch, RuntimeArch: map[string]string{"linux": "x86_64", "windows": "x86_64", "macos": "arm64"}[target.OS],
			Commit: commit, RunID: "13900", Status: "passed", ExitCode: 0, Checks: mkChecks(target.RequiredChecks), Artifacts: artifacts,
			Claims:      map[string]any{"guardProtocolVersion": 4, "releaseCertification": ver, "packagePlatform": map[string]string{"linux": "linux-amd64", "windows": "windows-amd64", "macos": "macos-universal"}[target.OS], "ciSigningMode": target.CISigningMode, "vendorSigningProvenance": "not-certified-by-ci", "packageManifestBound": true, "artifactSetComplete": true},
			Limitations: []string{guardCILimitation0139}, EvidenceSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		})
	}
	matrix := releaseGuardCIMatrix{SchemaVersion: "1.0", ProductVersion: ver, GeneratedAt: "2026-09-24T00:00:00Z", Repository: "DeepLayerTeam/NeverLauncher", Commit: commit, RunID: "13900", Status: "passed", Targets: results, Errors: []string{}}
	matrixRaw, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	matrixRaw = append(matrixRaw, '\n')
	matrixPath := filepath.Join(dir, "guard-ci-matrix.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return matrixPath, targetsPath
}

func TestGuardCICertificationRoundTrip0139(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	matrixPath, targetsPath := writeGuardCIEvidenceFixture(t, dir, out, "0.13.9", "abc139")
	if err := embedGuardCICertification(out, matrixPath, targetsPath, "0.13.9", "abc139"); err != nil {
		t.Fatal(err)
	}
	if err := verifyGuardCICertificationInBundle(out, "0.13.9"); err != nil {
		t.Fatal(err)
	}
	guardPath := filepath.Join(out, "neverguard-windows-amd64.exe")
	if err := os.WriteFile(guardPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyGuardCICertificationInBundle(out, "0.13.9"); err == nil {
		t.Fatal("Guard CI certification must reject a post-CI artifact replacement")
	}
}

func TestGuardCICertificationRejectsWeakenedMatrix0139(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	matrixPath, targetsPath := writeGuardCIEvidenceFixture(t, dir, out, "0.13.9", "abc139")
	matrixRaw, _ := os.ReadFile(matrixPath)
	var matrix releaseGuardCIMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	matrix.Targets[1].Checks["guardIntegrationTest"] = false
	matrixRaw, _ = json.Marshal(matrix)
	targetsRaw, _ := os.ReadFile(targetsPath)
	if _, err := validateGuardCIEvidence(matrixRaw, targetsRaw, "0.13.9", "abc139"); err == nil {
		t.Fatal("Guard certification must reject a target without required integration test")
	}
}

func TestGuardCICertificationRequiredFrom0139(t *testing.T) {
	if !guardCICertificationRequired("0.13.9") || !guardCICertificationRequired("0.14.0") {
		t.Fatal("0.13.9+ must require Guard CI certification")
	}
	if guardCICertificationRequired("0.13.8") {
		t.Fatal("0.13.8 must not retroactively require Guard CI certification")
	}
}

func TestReleasePublishCheckRequiresGuardCertification0139(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "release")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	ver := "0.13.9"
	for _, name := range releaseArtifacts(ver) {
		if name == "SBOM.spdx.json" || name == "PROVENANCE.json" || name == "RELEASE_NOTES.txt" {
			continue
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte("artifact\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	compatMatrix, compatTargets := writeCompatibilityEvidenceFixture(t, dir, ver, "abc139")
	dtMatrix, dtTargets := writeDeviceTrustEvidenceFixture(t, dir, ver, "abc139")
	guardMatrix, guardTargets := writeGuardCIEvidenceFixture(t, dir, out, ver, "abc139")
	if err := buildReleaseBundle(ver, out, ".", compatMatrix, compatTargets, dtMatrix, dtTargets, guardMatrix, guardTargets, "abc139"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signReleaseBundle(out, privatePath); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release", "publish-check", out, "--public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(out, guardCICertificationReleaseFile)); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release", "publish-check", out, "--public-key", publicPath}); err == nil {
		t.Fatal("0.13.9 publish-check must require Guard CI certification")
	}
}
