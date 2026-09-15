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

func writeCompatibilityEvidenceFixture(t *testing.T, dir, ver, commit string) (string, string) {
	t.Helper()
	targets := releaseCompatibilityTargets{
		SchemaVersion:  "1.0",
		ProductVersion: ver,
		Targets: []releaseCompatibilityTarget{
			{ID: "vanilla-1.21.1-linux-x64", Minecraft: "1.21.1", Loader: "vanilla", LoaderVersion: "", OS: "linux", Arch: "x86_64", Required: true},
			{ID: "fabric-1.21.1-linux-x64", Minecraft: "1.21.1", Loader: "fabric", LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64", Required: true},
		},
	}
	targetRaw, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	targetRaw = append(targetRaw, '\n')
	targetsPath := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(targetsPath, targetRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	checks := map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true}
	evidence := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	matrix := releaseCompatibilityMatrix{
		SchemaVersion: "1.0", ProductVersion: ver, GeneratedAt: "2026-09-15T00:00:00Z", Repository: "DeepLayerTeam/NeverLauncher", Commit: commit, RunID: "12345", Status: "passed", Errors: []string{},
		Targets: []releaseCompatibilityResult{
			{SchemaVersion: "1.0", ProductVersion: ver, TargetID: "vanilla-1.21.1-linux-x64", Status: "passed", MinecraftVersion: "1.21.1", Loader: "vanilla", LoaderSelector: "", OS: "linux", Arch: "x86_64", Commit: commit, RunID: "12345", ExitCode: 0, Checks: checks, EvidenceSHA256: evidence},
			{SchemaVersion: "1.0", ProductVersion: ver, TargetID: "fabric-1.21.1-linux-x64", Status: "passed", MinecraftVersion: "1.21.1", Loader: "fabric", LoaderSelector: "latest-stable", ResolvedLoaderVersion: "0.16.10", OS: "linux", Arch: "x86_64", Commit: commit, RunID: "12345", ExitCode: 0, Checks: checks, EvidenceSHA256: evidence},
		},
	}
	matrixRaw, err := json.MarshalIndent(matrix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	matrixRaw = append(matrixRaw, '\n')
	matrixPath := filepath.Join(dir, "matrix.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return matrixPath, targetsPath
}

func TestCompatibilityCertificationRejectsIncompleteEvidence(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.11.0", "abc123")
	raw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	matrix.Targets[1].Checks["paperJoin"] = false
	raw, _ = json.Marshal(matrix)
	targetRaw, _ := os.ReadFile(targetsPath)
	if _, err := validateCompatibilityEvidence(raw, targetRaw, "0.11.0", "abc123"); err == nil {
		t.Fatal("certification обязана отклонять target без paperJoin")
	}
}

func TestCompatibilityCertificationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.11.0", "abc123")
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedCompatibilityCertification(bundle, matrixPath, targetsPath, "0.11.0", "abc123"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.11.0"); err != nil {
		t.Fatal(err)
	}

	matrixFile := filepath.Join(bundle, compatibilityMatrixReleaseFile)
	raw, err := os.ReadFile(matrixFile)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte(" \n")...)
	if err := os.WriteFile(matrixFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.11.0"); err == nil {
		t.Fatal("certification обязана обнаруживать изменение embedded matrix")
	}
}

func TestReleasePublishCheckRequiresCompatibilityCertificationFor011(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "release")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	ver := "0.11.0"
	for _, name := range releaseArtifacts(ver) {
		if name == "SBOM.spdx.json" || name == "PROVENANCE.json" || name == "RELEASE_NOTES.txt" {
			continue
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte("artifact\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, ver, "abc123")
	if err := buildReleaseBundle(ver, out, ".", matrixPath, targetsPath, "abc123"); err != nil {
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
}

func TestCompatibilityCertificationRejectsSourceCommitMismatch(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.11.0", "commit-a")
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.11.0", "commit-b"); err == nil {
		t.Fatal("certification обязана отклонять matrix от другого source commit")
	}
}

func TestCompatibilityReleaseRequiresCertificationOnlyAtPublishGate(t *testing.T) {
	if !compatibilityCertificationRequired("0.11.0") {
		t.Fatal("0.11.0 должен требовать compatibility certification")
	}
	if compatibilityCertificationRequired("0.10.7") {
		t.Fatal("0.10.7 не должен ретроактивно требовать compatibility certification")
	}
}
