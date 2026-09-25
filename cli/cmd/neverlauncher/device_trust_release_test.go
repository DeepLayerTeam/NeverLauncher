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

func writeDeviceTrustEvidenceFixture(t *testing.T, dir, ver, commit string) (string, string) {
	t.Helper()
	protocolChecks := []string{
		"postgresRepository", "migrationStabilization01210", "registrationReplayDenied", "sessionBindingEpoch",
		"boundRefreshProof", "rotationDualProof", "oldKeyTombstone", "serverBridgeBindingDeny", "revocationCascade",
		"riskStepUp", "p256AttestationProtocol", "attestationReplayDenied", "recoveryRequiresPhishingResistantStepUp",
		"recoveryPhishingResistantEndToEnd", "deviceTrustRelease0130",
	}
	nativeChecks := []string{
		"tauriCompile", "deviceKeyUnitTests", "generationScopedHardwareLabels", "replacementPayloadValidation",
		"refreshPayloadBinding", "attestationPayloadValidation", "deviceTrustRelease0130",
	}
	targets := releaseDeviceTrustTargets{SchemaVersion: "1.0", ProductVersion: ver, Targets: []releaseDeviceTrustTarget{
		{ID: "postgres-protocol-linux-x64", Kind: "protocol-e2e", Runner: "ubuntu-24.04", OS: "linux", Arch: "x86_64", Required: true, RequiredChecks: protocolChecks},
		{ID: "native-linux", Kind: "native-tests", Runner: "ubuntu-24.04", OS: "linux", Arch: "runner-native", Required: true, RequiredChecks: nativeChecks},
		{ID: "native-windows", Kind: "native-tests", Runner: "windows-2022", OS: "windows", Arch: "runner-native", Required: true, RequiredChecks: nativeChecks},
		{ID: "native-macos", Kind: "native-tests", Runner: "macos-14", OS: "macos", Arch: "runner-native", Required: true, RequiredChecks: nativeChecks},
	}}
	targetsRaw, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw = append(targetsRaw, '\n')
	targetsPath := filepath.Join(dir, "device-trust-targets.json")
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
	evidence := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	results := []releaseDeviceTrustResult{
		{SchemaVersion: "1.0", ProductVersion: ver, TargetID: "postgres-protocol-linux-x64", Kind: "protocol-e2e", OS: "linux", Arch: "x86_64", RuntimeArch: "x86_64", Commit: commit, RunID: "13000", Status: "passed", ExitCode: 0, Checks: mkChecks(protocolChecks), EvidenceSHA256: evidence, Claims: map[string]any{"repository": "postgresql", "vendorHardwareProvenance": "not-verified", "privateKeyServerExposed": false, "deviceTrustRelease": ver}},
	}
	for _, tc := range []struct{ id, os, runtime string }{{"native-linux", "linux", "x86_64"}, {"native-windows", "windows", "x86_64"}, {"native-macos", "macos", "arm64"}} {
		results = append(results, releaseDeviceTrustResult{SchemaVersion: "1.0", ProductVersion: ver, TargetID: tc.id, Kind: "native-tests", OS: tc.os, Arch: "runner-native", RuntimeArch: tc.runtime, Commit: commit, RunID: "13000", Status: "passed", ExitCode: 0, Checks: mkChecks(nativeChecks), EvidenceSHA256: evidence, Claims: map[string]any{"deviceTrustRelease": ver}, Limitations: []string{"headless-ci-does-not-prove-os-secure-storage-runtime"}})
	}
	matrix := releaseDeviceTrustMatrix{SchemaVersion: "1.0", ProductVersion: ver, GeneratedAt: "2026-09-22T00:00:00Z", Repository: "DeepLayerTeam/NeverLauncher", Commit: commit, RunID: "13000", Status: "passed", Targets: results, Errors: []string{}}
	matrixRaw, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	matrixRaw = append(matrixRaw, '\n')
	matrixPath := filepath.Join(dir, "device-trust-matrix.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return matrixPath, targetsPath
}

func TestDeviceTrustCertificationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeDeviceTrustEvidenceFixture(t, dir, "0.13.0", "abc130")
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedDeviceTrustCertification(bundle, matrixPath, targetsPath, "0.13.0", "abc130"); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceTrustCertificationInBundle(bundle, "0.13.0"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(bundle, deviceTrustMatrixReleaseFile))
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte(" \n")...)
	if err := os.WriteFile(filepath.Join(bundle, deviceTrustMatrixReleaseFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceTrustCertificationInBundle(bundle, "0.13.0"); err == nil {
		t.Fatal("certification обязана обнаруживать изменение embedded Device Trust matrix")
	}
}

func TestDeviceTrustCertificationRejectsIncompleteEvidence(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeDeviceTrustEvidenceFixture(t, dir, "0.13.0", "abc130")
	raw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	var matrix releaseDeviceTrustMatrix
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	matrix.Targets[0].Checks["rotationDualProof"] = false
	raw, _ = json.Marshal(matrix)
	targetRaw, _ := os.ReadFile(targetsPath)
	if _, err := validateDeviceTrustEvidence(raw, targetRaw, "0.13.0", "abc130"); err == nil {
		t.Fatal("certification обязана отклонять protocol target без rotationDualProof")
	}
}

func TestDeviceTrustCertificationRejectsSourceCommitMismatch(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeDeviceTrustEvidenceFixture(t, dir, "0.13.0", "commit-a")
	matrixRaw, _ := os.ReadFile(matrixPath)
	targetsRaw, _ := os.ReadFile(targetsPath)
	if _, err := validateDeviceTrustEvidence(matrixRaw, targetsRaw, "0.13.0", "commit-b"); err == nil {
		t.Fatal("certification обязана отклонять matrix от другого source commit")
	}
}

func TestDeviceTrustCertificationRequiredFrom013(t *testing.T) {
	if !deviceTrustCertificationRequired("0.13.0") {
		t.Fatal("0.13.0 должен требовать Device Trust certification")
	}
	if deviceTrustCertificationRequired("0.12.10") {
		t.Fatal("0.12.10 не должен ретроактивно требовать Device Trust certification")
	}
}

func TestReleasePublishCheckAcceptsDeviceTrustCertificationFor013(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "release")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	ver := "0.13.0"
	for _, name := range releaseArtifacts(ver) {
		if name == "SBOM.spdx.json" || name == "PROVENANCE.json" || name == "RELEASE_NOTES.txt" {
			continue
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte("artifact\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	compatMatrix, compatTargets := writeCompatibilityEvidenceFixture(t, dir, ver, "abc130")
	dtMatrix, dtTargets := writeDeviceTrustEvidenceFixture(t, dir, ver, "abc130")
	if err := buildReleaseBundle(ver, out, ".", compatMatrix, compatTargets, dtMatrix, dtTargets, "", "guard-ci/targets.json", "abc130", ""); err != nil {
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
	if err := os.Remove(filepath.Join(out, deviceTrustCertificationReleaseFile)); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release", "publish-check", out, "--public-key", publicPath}); err == nil {
		t.Fatal("0.13.0 publish-check обязан требовать Device Trust certification")
	}
}
