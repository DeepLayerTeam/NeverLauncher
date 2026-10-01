package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeCompatibilityEvidenceFixture(t *testing.T, dir, ver, commit string) (string, string) {
	t.Helper()
	targets := releaseCompatibilityTargets{
		SchemaVersion: "1.0",
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

func TestCompatibilityCertificationAcceptsVersionlessTargetsFromRepositoryContract(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.16.1", "abc123")
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	var targetDocument map[string]any
	if err := json.Unmarshal(targetsRaw, &targetDocument); err != nil {
		t.Fatal(err)
	}
	if _, exists := targetDocument["productVersion"]; exists {
		t.Fatal("repository-style compatibility targets must not duplicate VERSION")
	}
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.1", "abc123")
	if err != nil {
		t.Fatalf("versionless compatibility targets must derive product version from release VERSION: %v", err)
	}
	if certification.ProductVersion != "0.16.1" {
		t.Fatalf("certification productVersion=%q, want 0.16.1", certification.ProductVersion)
	}
}

func TestCompatibilityCertificationRejectsExplicitTargetsVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.16.1", "abc123")
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	var targets map[string]any
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	targets["productVersion"] = "0.16.0"
	targetsRaw, err = json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.1", "abc123"); err == nil {
		t.Fatal("explicit compatibility targets productVersion mismatch must fail closed")
	}
}

func TestCompatibilityCertificationRejectsMatrixVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	matrixPath, targetsPath := writeCompatibilityEvidenceFixture(t, dir, "0.16.1", "abc123")
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	matrix.ProductVersion = "0.16.0"
	matrixRaw, err = json.Marshal(matrix)
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.1", "abc123"); err == nil {
		t.Fatal("compatibility matrix productVersion mismatch must fail closed")
	}
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
	if err := buildReleaseBundle(ver, out, ".", matrixPath, targetsPath, "", "device-trust/targets.json", "", "guard-ci/targets.json", "abc123", ""); err != nil {
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

func vanillaBaselineIIEvidenceFixture(t *testing.T, ver, commit string) ([]byte, []byte) {
	t.Helper()
	versions := make([]string, 0, len(vanillaCompatibilityBaselineII))
	for minecraft := range vanillaCompatibilityBaselineII {
		versions = append(versions, minecraft)
	}
	sort.Strings(versions)
	targets := releaseCompatibilityTargets{SchemaVersion: "1.0", ProductVersion: ver}
	matrix := releaseCompatibilityMatrix{
		SchemaVersion: "1.0", ProductVersion: ver, GeneratedAt: "2026-10-01T00:00:00Z",
		Repository: "DeepLayerTeam/NeverLauncher", Commit: commit, RunID: "162", Status: "passed", Errors: []string{},
	}
	evidence := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, minecraft := range versions {
		expected := vanillaCompatibilityBaselineII[minecraft]
		id := "vanilla-" + minecraft + "-linux-x64"
		targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
			ID: id, Minecraft: minecraft, Loader: "vanilla", OS: "linux", Arch: "x86_64",
			JavaMajor: expected.JavaMajor, Scope: expected.Scope, Required: true,
		})
		checks := map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "actualClient": true}
		if expected.Scope == "integration" {
			checks = map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true}
		}
		matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: minecraft,
			Loader: "vanilla", OS: "linux", Arch: "x86_64", JavaMajor: expected.JavaMajor, DetectedJavaMajor: expected.JavaMajor,
			Scope: expected.Scope, Commit: commit, RunID: "162", ExitCode: 0, Checks: checks, EvidenceSHA256: evidence,
		})
	}
	for _, loader := range []string{"fabric", "quilt", "forge", "neoforge"} {
		id := loader + "-1.21.1-linux-x64"
		targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
			ID: id, Minecraft: "1.21.1", Loader: loader, LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
			JavaMajor: 21, Scope: "integration", Required: true,
		})
		matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: "1.21.1",
			Loader: loader, LoaderSelector: "latest-stable", ResolvedLoaderVersion: "1.0.0", OS: "linux", Arch: "x86_64",
			JavaMajor: 21, DetectedJavaMajor: 21, Scope: "integration", Commit: commit, RunID: "162", ExitCode: 0,
			Checks:         map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true},
			EvidenceSHA256: evidence,
		})
	}
	targetRaw, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	matrixRaw, err := json.Marshal(matrix)
	if err != nil {
		t.Fatal(err)
	}
	return matrixRaw, targetRaw
}

func TestCompatibilityCertificationVanillaBaselineII(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.2", "commit-162")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.2", "commit-162")
	if err != nil {
		t.Fatalf("0.16.2 Baseline II evidence must pass: %v", err)
	}
	if certification.Policy != "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact" {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	if len(certification.VanillaVersions) != len(vanillaCompatibilityBaselineII) {
		t.Fatalf("vanilla coverage=%v", certification.VanillaVersions)
	}
	if got := fmt.Sprint(certification.JavaMajors); got != "[8 16 17 21]" {
		t.Fatalf("java coverage=%s", got)
	}
	if got := strings.Join(certification.Scopes, ","); got != "client,integration" {
		t.Fatalf("scope coverage=%s", got)
	}
}

func TestCompatibilityCertificationVanillaBaselineIIRejectsJavaMismatch(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.2", "commit-162")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].MinecraftVersion == "1.17.1" && matrix.Targets[i].Loader == "vanilla" {
			matrix.Targets[i].DetectedJavaMajor = 17
			matrix.Targets[i].Checks["javaMatched"] = false
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.2", "commit-162"); err == nil {
		t.Fatal("0.16.2 Baseline II must reject Java mismatch")
	}
}

func TestCompatibilityCertificationVanillaBaselineIIRejectsMissingAnchor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.2", "commit-162")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.12.2" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.2", "commit-162"); err == nil {
		t.Fatal("0.16.2 Baseline II must reject missing anchor")
	}
}
