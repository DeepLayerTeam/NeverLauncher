package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	versionsSet := map[string]struct{}{}
	for minecraft := range vanillaCompatibilityBaselineII {
		versionsSet[minecraft] = struct{}{}
	}
	if compatibilityLegacyVanillaJava8Required(ver) {
		for _, minecraft := range legacyVanillaJava8Compatibility0163 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityLegacyVanillaPre17Required(ver) {
		for _, minecraft := range legacyVanillaPre17Compatibility0164 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityJava16_17VanillaRequired(ver) {
		for minecraft := range java16_17VanillaCompatibility0166 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityJava21VanillaRequired(ver) {
		for minecraft := range java21VanillaCompatibility0167 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityJava25VanillaRequired(ver) {
		for minecraft := range java25VanillaCompatibility0168 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityActualClientE2EIIRequired(ver) {
		for minecraft := range actualClientE2EIICompatibility01610 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityLegacyVanilla0170v1Required(ver) {
		for _, minecraft := range legacyVanilla0170v1Releases {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityJava16_17Vanilla0170v2Required(ver) {
		for minecraft := range java16_17VanillaCompatibility0170v2 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	if compatibilityJava21_25Vanilla0170v3Required(ver) {
		for minecraft := range java21_25VanillaCompatibility0170v3 {
			versionsSet[minecraft] = struct{}{}
		}
	}
	versions := make([]string, 0, len(versionsSet))
	for minecraft := range versionsSet {
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
		expected, ok := vanillaCompatibilityBaselineII[minecraft]
		if !ok {
			if javaMajor, modernV3 := java21_25VanillaCompatibility0170v3[minecraft]; modernV3 {
				expected.JavaMajor = javaMajor
				expected.Scope = "client"
			} else if javaMajor, modernV2 := java16_17VanillaCompatibility0170v2[minecraft]; modernV2 {
				expected.JavaMajor = javaMajor
				expected.Scope = "client"
			} else if javaMajor, modern := java16_17VanillaCompatibility0166[minecraft]; modern {
				expected.JavaMajor = javaMajor
				expected.Scope = "client"
			} else if scope, modern21 := java21VanillaCompatibility0167[minecraft]; modern21 {
				expected.JavaMajor = 21
				expected.Scope = scope
			} else if scope, modern25 := java25VanillaCompatibility0168[minecraft]; modern25 {
				expected.JavaMajor = 25
				expected.Scope = scope
			} else {
				expected.JavaMajor = 8
				expected.Scope = "client"
			}
		} else if scope, modern21 := java21VanillaCompatibility0167[minecraft]; modern21 {
			// 1.20.6 and 1.21.1 are Baseline II anchors but 0.16.7 keeps
			// the stricter release-line scope binding authoritative.
			expected.JavaMajor = 21
			expected.Scope = scope
		}
		matchingServer := false
		if _, required := actualClientE2EIICompatibility01610[minecraft]; compatibilityActualClientE2EIIRequired(ver) && required {
			matchingServer = true
		}
		id := "vanilla-" + minecraft + "-linux-x64"
		targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
			ID: id, Minecraft: minecraft, Loader: "vanilla", OS: "linux", Arch: "x86_64",
			JavaMajor: expected.JavaMajor, Scope: expected.Scope, MatchingServer: matchingServer, Required: true,
		})
		checks := map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "jreCertified": true, "actualClient": true}
		if expected.Scope == "integration" {
			checks = map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true, "jreCertified": true}
		}
		if compatibilityCrossPlatformVanillaRequired(ver) {
			checks["platformMatched"] = true
		}
		if matchingServer {
			checks["matchingServer"] = true
			checks["serverVersionMatched"] = true
			checks["serverHealthy"] = true
			checks["clientJoinedServer"] = true
		}
		matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: minecraft,
			Loader: "vanilla", OS: "linux", Arch: "x86_64", JavaMajor: expected.JavaMajor, DetectedJavaMajor: expected.JavaMajor,
			JREVendor: "Eclipse Adoptium", JRERuntimeVersion: fmt.Sprintf("%d.0.0+ga", expected.JavaMajor), JREExecutableSHA256: evidence,
			Scope: expected.Scope, MatchingServer: matchingServer, Commit: commit, RunID: "162", ExitCode: 0, Checks: checks, EvidenceSHA256: evidence,
		})
	}
	if compatibilityCrossPlatformVanillaRequired(ver) {
		for _, platform := range crossPlatformVanillaCompatibility0169 {
			if platform.OS == "linux" && platform.Arch == "x86_64" {
				continue
			}
			id := "vanilla-26.3-" + platform.OS + "-" + platform.Arch
			targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
				ID: id, Minecraft: "26.3", Loader: "vanilla", OS: platform.OS, Arch: platform.Arch,
				JavaMajor: 25, Scope: "client", Required: true,
			})
			matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
				SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: "26.3",
				Loader: "vanilla", OS: platform.OS, Arch: platform.Arch, JavaMajor: 25, DetectedJavaMajor: 25, Scope: "client",
				Commit: commit, RunID: "162", ExitCode: 0,
				Checks:    map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "jreCertified": true, "actualClient": true, "platformMatched": true},
				JREVendor: "Eclipse Adoptium", JRERuntimeVersion: "25.0.0+ga", JREExecutableSHA256: evidence,
				EvidenceSHA256: evidence,
			})
		}
	}
	if compatibilityFabricII0171Required(ver) {
		fabricVersions := make([]string, 0, len(fabricCompatibilityII0171))
		for minecraft := range fabricCompatibilityII0171 {
			fabricVersions = append(fabricVersions, minecraft)
		}
		sort.Strings(fabricVersions)
		for _, minecraft := range fabricVersions {
			javaMajor := fabricCompatibilityII0171[minecraft]
			scope := "client"
			if minecraft == "1.21.1" {
				scope = "integration"
			}
			id := "fabric-" + minecraft + "-linux-x64"
			targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
				ID: id, Minecraft: minecraft, Loader: "fabric", LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, Scope: scope, Required: true,
			})
			checks := map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "actualClient": true, "platformMatched": true, "jreCertified": true}
			if scope == "integration" {
				checks = map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true, "platformMatched": true, "jreCertified": true}
			}
			matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
				SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: minecraft,
				Loader: "fabric", LoaderSelector: "latest-stable", ResolvedLoaderVersion: "0.19.5", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, DetectedJavaMajor: javaMajor, JREVendor: "Eclipse Adoptium", JRERuntimeVersion: fmt.Sprintf("%d.0.0+ga", javaMajor), JREExecutableSHA256: evidence, Scope: scope, Commit: commit, RunID: "162", ExitCode: 0,
				Checks: checks, EvidenceSHA256: evidence,
			})
		}
	}
	if compatibilityQuiltII0172Required(ver) {
		quiltVersions := make([]string, 0, len(quiltCompatibilityII0172))
		for minecraft := range quiltCompatibilityII0172 {
			quiltVersions = append(quiltVersions, minecraft)
		}
		sort.Strings(quiltVersions)
		for _, minecraft := range quiltVersions {
			javaMajor := quiltCompatibilityII0172[minecraft]
			scope := "client"
			if minecraft == "1.21.1" {
				scope = "integration"
			}
			id := "quilt-" + minecraft + "-linux-x64"
			targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
				ID: id, Minecraft: minecraft, Loader: "quilt", LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, Scope: scope, Required: true,
			})
			checks := map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "actualClient": true, "platformMatched": true, "jreCertified": true}
			if scope == "integration" {
				checks = map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true, "platformMatched": true, "jreCertified": true}
			}
			matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
				SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: minecraft,
				Loader: "quilt", LoaderSelector: "latest-stable", ResolvedLoaderVersion: "0.31.0", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, DetectedJavaMajor: javaMajor, JREVendor: "Eclipse Adoptium", JRERuntimeVersion: fmt.Sprintf("%d.0.0+ga", javaMajor), JREExecutableSHA256: evidence, Scope: scope, Commit: commit, RunID: "162", ExitCode: 0,
				Checks: checks, EvidenceSHA256: evidence,
			})
		}
	}

	if compatibilityForgeModern0173Required(ver) {
		forgeVersions := make([]string, 0, len(forgeModern0173))
		for minecraft := range forgeModern0173 {
			forgeVersions = append(forgeVersions, minecraft)
		}
		sort.Strings(forgeVersions)
		for _, minecraft := range forgeVersions {
			javaMajor := forgeModern0173[minecraft]
			scope := "client"
			if minecraft == "1.21.1" {
				scope = "integration"
			}
			id := "forge-" + minecraft + "-linux-x64"
			targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
				ID: id, Minecraft: minecraft, Loader: "forge", LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, Scope: scope, Required: true,
			})
			checks := map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "actualClient": true, "platformMatched": true, "jreCertified": true}
			if scope == "integration" {
				checks = map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true, "platformMatched": true, "jreCertified": true}
			}
			matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
				SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: minecraft,
				Loader: "forge", LoaderSelector: "latest-stable", ResolvedLoaderVersion: "61.2.1", OS: "linux", Arch: "x86_64",
				JavaMajor: javaMajor, DetectedJavaMajor: javaMajor, JREVendor: "Eclipse Adoptium", JRERuntimeVersion: fmt.Sprintf("%d.0.0+ga", javaMajor), JREExecutableSHA256: evidence, Scope: scope, Commit: commit, RunID: "162", ExitCode: 0,
				Checks: checks, EvidenceSHA256: evidence,
			})
		}
	}

	if compatibilityForgeLegacy1122_0174Required(ver) {
		id := "forge-1.12.2-linux-x64"
		targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
			ID: id, Minecraft: "1.12.2", Loader: "forge", LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
			JavaMajor: 8, Scope: "client", Required: true,
		})
		matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: "1.12.2",
			Loader: "forge", LoaderSelector: "latest-stable", ResolvedLoaderVersion: "14.23.5.2864", OS: "linux", Arch: "x86_64",
			JavaMajor: 8, DetectedJavaMajor: 8, JREVendor: "Eclipse Adoptium", JRERuntimeVersion: "8.0.0+ga", JREExecutableSHA256: evidence, Scope: "client", Commit: commit, RunID: "162", ExitCode: 0,
			Checks: map[string]bool{"materialized": true, "packageVerified": true, "runtimeResolved": true, "javaMatched": true, "actualClient": true, "platformMatched": true, "jreCertified": true}, EvidenceSHA256: evidence,
		})
	}

	for _, loader := range []string{"fabric", "quilt", "forge", "neoforge"} {
		if loader == "fabric" && compatibilityFabricII0171Required(ver) {
			continue
		}
		if loader == "quilt" && compatibilityQuiltII0172Required(ver) {
			continue
		}
		if loader == "forge" && compatibilityForgeModern0173Required(ver) {
			continue
		}
		id := loader + "-1.21.1-linux-x64"
		targets.Targets = append(targets.Targets, releaseCompatibilityTarget{
			ID: id, Minecraft: "1.21.1", Loader: loader, LoaderVersion: "latest-stable", OS: "linux", Arch: "x86_64",
			JavaMajor: 21, Scope: "integration", Required: true,
		})
		loaderChecks := map[string]bool{"actualClient": true, "packageVerified": true, "signedManifest": true, "cleanSync": true, "paperJoin": true, "sessionRevokeDeny": true, "paperHealthy": true, "javaMatched": true, "jreCertified": true}
		if compatibilityCrossPlatformVanillaRequired(ver) {
			loaderChecks["platformMatched"] = true
		}
		matrix.Targets = append(matrix.Targets, releaseCompatibilityResult{
			SchemaVersion: "1.0", ProductVersion: ver, TargetID: id, Status: "passed", MinecraftVersion: "1.21.1",
			Loader: loader, LoaderSelector: "latest-stable", ResolvedLoaderVersion: "1.0.0", OS: "linux", Arch: "x86_64",
			JavaMajor: 21, DetectedJavaMajor: 21, JREVendor: "Eclipse Adoptium", JRERuntimeVersion: "21.0.0+ga", JREExecutableSHA256: evidence, Scope: "integration", Commit: commit, RunID: "162", ExitCode: 0,
			Checks:         loaderChecks,
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

func TestCompatibilityCertificationLegacyVanilla0163(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.3", "commit-163")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.3", "commit-163")
	if err != nil {
		t.Fatalf("0.16.3 Legacy Vanilla evidence must pass: %v", err)
	}
	wantPolicy := "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8"
	if certification.Policy != wantPolicy {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	for _, minecraft := range legacyVanillaJava8Compatibility0163 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("legacy Vanilla version %s missing from certification: %v", minecraft, certification.VanillaVersions)
		}
	}
}

func TestCompatibilityCertificationLegacyVanilla0163RejectsMissingReleaseLine(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.3", "commit-163")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.8.9" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.3", "commit-163"); err == nil {
		t.Fatal("0.16.3 must reject missing legacy Vanilla release line")
	}
}
func TestCompatibilityCertificationLegacyVanilla0164(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.4", "commit-164")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.4", "commit-164")
	if err != nil {
		t.Fatalf("0.16.4 pre-1.7 Legacy Vanilla evidence must pass: %v", err)
	}
	wantPolicy := "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8;legacy-vanilla-1.0-1.7.10-java8"
	if certification.Policy != wantPolicy {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	for _, minecraft := range legacyVanillaPre17Compatibility0164 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("pre-1.7 Vanilla version %s missing from certification: %v", minecraft, certification.VanillaVersions)
		}
	}
}

func TestCompatibilityCertificationLegacyVanilla0164RejectsMissingReleaseLine(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.4", "commit-164")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.2.5" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.4", "commit-164"); err == nil {
		t.Fatal("0.16.4 must reject missing pre-1.7 Vanilla release line")
	}
}

func TestCompatibilityCertificationJava16_17Vanilla0166(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.6", "commit-166")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.6", "commit-166")
	if err != nil {
		t.Fatalf("0.16.6 Java 16/17 Vanilla evidence must pass: %v", err)
	}
	wantPolicy := "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8;legacy-vanilla-1.0-1.7.10-java8;vanilla-1.17.1-1.20.4-java16-17-exact"
	if certification.Policy != wantPolicy {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	for minecraft, javaMajor := range java16_17VanillaCompatibility0166 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("Java 16/17 Vanilla version %s missing from certification: %v", minecraft, certification.VanillaVersions)
		}
		_ = javaMajor
	}
}

func TestCompatibilityCertificationJava16_17Vanilla0166RejectsMissingReleaseLine(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.6", "commit-166")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.20.2" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.6", "commit-166"); err == nil {
		t.Fatal("0.16.6 must reject missing Java 16/17 Vanilla release line")
	}
}

func TestCompatibilityCertificationJava16_17Vanilla0166RejectsWrongMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.6", "commit-166")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "vanilla" && targets.Targets[i].Minecraft == "1.19.4" {
			targets.Targets[i].JavaMajor = 16
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.6", "commit-166"); err == nil {
		t.Fatal("0.16.6 must reject wrong Java major for 1.19.4")
	}
}

func TestCompatibilityCertificationJava21Vanilla0167(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.7", "commit-167")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.7", "commit-167")
	if err != nil {
		t.Fatalf("0.16.7 Java 21 Vanilla evidence must pass: %v", err)
	}
	wantPolicy := "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8;legacy-vanilla-1.0-1.7.10-java8;vanilla-1.17.1-1.20.4-java16-17-exact;vanilla-1.20.5-1.21.10-java21-exact"
	if certification.Policy != wantPolicy {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	for minecraft := range java21VanillaCompatibility0167 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("Java 21 Vanilla version %s missing from certification: %v", minecraft, certification.VanillaVersions)
		}
	}
}

func TestCompatibilityCertificationJava21Vanilla0167RejectsMissingReleaseLine(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.7", "commit-167")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.21.10" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.7", "commit-167"); err == nil {
		t.Fatal("0.16.7 must reject missing Java 21 Vanilla release line")
	}
}

func TestCompatibilityCertificationJava21Vanilla0167RejectsWrongMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.7", "commit-167")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "vanilla" && targets.Targets[i].Minecraft == "1.21.10" {
			targets.Targets[i].JavaMajor = 17
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.7", "commit-167"); err == nil {
		t.Fatal("0.16.7 must reject wrong Java major for 1.21.10")
	}
}

func TestCompatibilityCertificationJava25Vanilla0168(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.8", "commit-168")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.8", "commit-168")
	if err != nil {
		t.Fatalf("0.16.8 Java 25 Vanilla evidence must pass: %v", err)
	}
	wantPolicy := "all-required-targets-must-pass;vanilla-baseline-ii-multiversion-java-exact;legacy-vanilla-1.7.10-1.16.5-java8;legacy-vanilla-1.0-1.7.10-java8;vanilla-1.17.1-1.20.4-java16-17-exact;vanilla-1.20.5-1.21.10-java21-exact;vanilla-26.1.x-26.3-java25-exact"
	if certification.Policy != wantPolicy {
		t.Fatalf("unexpected policy: %s", certification.Policy)
	}
	for minecraft := range java25VanillaCompatibility0168 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("Java 25 Vanilla version %s missing from certification: %v", minecraft, certification.VanillaVersions)
		}
	}
	if !slices.Contains(certification.JavaMajors, 25) {
		t.Fatalf("Java 25 missing from certification coverage: %v", certification.JavaMajors)
	}
}

func TestCompatibilityCertificationJava25Vanilla0168RejectsMissingRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.8", "commit-168")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "26.3" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.8", "commit-168"); err == nil {
		t.Fatal("0.16.8 must reject missing Java 25 Vanilla release")
	}
}

func TestCompatibilityCertificationJava25Vanilla0168RejectsWrongMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.8", "commit-168")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "vanilla" && targets.Targets[i].Minecraft == "26.1.2" {
			targets.Targets[i].JavaMajor = 21
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.8", "commit-168"); err == nil {
		t.Fatal("0.16.8 must reject wrong Java major for 26.1.2")
	}
}

func TestCompatibilityCertificationCrossPlatformVanilla0169(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.9", "commit-169")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.9", "commit-169")
	if err != nil {
		t.Fatalf("0.16.9 cross-platform Vanilla evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "cross-platform-vanilla-windows-linux-macos-x64-arm64") {
		t.Fatalf("cross-platform policy missing: %s", certification.Policy)
	}
}

func TestCompatibilityCertificationCrossPlatformVanilla0169RejectsMissingPlatform(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.9", "commit-169")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "26.3" && target.OS == "windows" && target.Arch == "aarch64" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.9", "commit-169"); err == nil {
		t.Fatal("0.16.9 must reject missing Windows ARM64 Vanilla certification target")
	}
}

func TestCompatibilityCertificationCrossPlatformVanilla0169RejectsPlatformMismatch(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.9", "commit-169")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].TargetID == "vanilla-26.3-macos-aarch64" {
			matrix.Targets[i].Checks["platformMatched"] = false
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.9", "commit-169"); err == nil {
		t.Fatal("0.16.9 must reject host platform mismatch evidence")
	}
}

func TestCompatibilityCertificationActualClientE2EII01610(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.10", "commit-1610")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.10", "commit-1610")
	if err != nil {
		t.Fatalf("0.16.10 Actual Client E2E II evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "actual-client-e2e-II-real-clients-matching-mojang-servers") {
		t.Fatalf("0.16.10 policy does not bind matching servers: %s", certification.Policy)
	}
}

func TestCompatibilityCertificationActualClientE2EII01610RejectsMissingJoin(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.10", "commit-1610")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].MinecraftVersion == "1.20.4" && matrix.Targets[i].MatchingServer {
			matrix.Targets[i].Checks["clientJoinedServer"] = false
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.10", "commit-1610"); err == nil {
		t.Fatal("0.16.10 must reject matching-server target without a real client join")
	}
}

func TestCompatibilityCertificationActualClientE2EII01610RejectsMissingMatchingFlag(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.10", "commit-1610")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Minecraft == "1.17.1" && targets.Targets[i].OS == "linux" && targets.Targets[i].Arch == "x86_64" {
			targets.Targets[i].MatchingServer = false
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.10", "commit-1610"); err == nil {
		t.Fatal("0.16.10 must reject missing required matching-server target")
	}
}

func TestCompatibilityCertificationHardening01611Policy(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.16.11", "commit-1611")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.16.11", "commit-1611")
	if err != nil {
		t.Fatalf("0.16.11 compatibility evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "compatibility-hardening-cache-recovery-upstream-failure-security") {
		t.Fatalf("0.16.11 policy does not bind compatibility hardening: %s", certification.Policy)
	}
}

func TestCompatibilityCertificationGA0170BindsJREBase(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170")
	if err != nil {
		t.Fatalf("0.17.0 GA compatibility evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base") {
		t.Fatalf("0.17.0 policy does not bind GA JRE base: %s", certification.Policy)
	}
	if !strings.Contains(certification.Policy, "legacy-vanilla-0.17.0v1-complete-53-release-grid-java8") {
		t.Fatalf("0.17.0v1 policy does not bind complete legacy grid: %s", certification.Policy)
	}
	if len(certification.VanillaVersions) < 104 {
		t.Fatalf("0.17.0v3 GA Vanilla coverage too small: %d", len(certification.VanillaVersions))
	}
	if got := fmt.Sprint(certification.JavaMajors); got != "[8 16 17 21 25]" {
		t.Fatalf("0.17.0 GA Java coverage=%s", got)
	}
	if len(certification.JREBuilds) == 0 {
		t.Fatal("0.17.0 GA certification must contain concrete JRE builds")
	}
}

func TestCompatibilityCertificationGA0170v1RejectsMissingLegacyRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.8.8" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170"); err == nil || !strings.Contains(err.Error(), "0.17.0v1") {
		t.Fatalf("0.17.0v1 must reject missing 1.8.8 target, got %v", err)
	}
}

func TestCompatibilityCertificationGA0170v2RequiresCompleteJava16_17Grid(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v2")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v2")
	if err != nil {
		t.Fatalf("0.17.0v2 Java 16/17 evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "java16-17-vanilla-0.17.0v2-complete-9-release-grid-exact") {
		t.Fatalf("0.17.0v2 policy missing: %s", certification.Policy)
	}
	for minecraft := range java16_17VanillaCompatibility0170v2 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("0.17.0v2 version %s missing", minecraft)
		}
	}
}

func TestCompatibilityCertificationGA0170v2RejectsMissingJavaTransitionRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v2")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.19.2" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v2"); err == nil || !strings.Contains(err.Error(), "0.17.0v2") {
		t.Fatalf("0.17.0v2 must reject missing 1.19.2 target, got %v", err)
	}
}

func TestCompatibilityCertificationGA0170v2RejectsWrongJavaMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v2")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "vanilla" && targets.Targets[i].Minecraft == "1.17" {
			targets.Targets[i].JavaMajor = 17
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v2"); err == nil || !strings.Contains(err.Error(), "0.17.0v2") {
		t.Fatalf("0.17.0v2 must reject Java mismatch, got %v", err)
	}
}

func TestCompatibilityCertificationGA0170v3RequiresJava21And25Grid(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v3")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v3")
	if err != nil {
		t.Fatalf("0.17.0v3 Java 21/25 evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "java21-25-vanilla-0.17.0v3-complete-2-release-grid-exact") {
		t.Fatalf("0.17.0v3 policy missing: %s", certification.Policy)
	}
	for minecraft := range java21_25VanillaCompatibility0170v3 {
		if !slices.Contains(certification.VanillaVersions, minecraft) {
			t.Fatalf("0.17.0v3 version %s missing", minecraft)
		}
	}
}

func TestCompatibilityCertificationGA0170v3RejectsMissingRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v3")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "vanilla" && target.Minecraft == "1.21.11" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v3"); err == nil || !strings.Contains(err.Error(), "0.17.0v3") {
		t.Fatalf("0.17.0v3 must reject missing 1.21.11 target, got %v", err)
	}
}

func TestCompatibilityCertificationGA0170v3RejectsWrongJavaMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170-v3")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "vanilla" && targets.Targets[i].Minecraft == "26.2" {
			targets.Targets[i].JavaMajor = 21
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170-v3"); err == nil || !strings.Contains(err.Error(), "0.17.0v3") {
		t.Fatalf("0.17.0v3 must reject Java mismatch for 26.2, got %v", err)
	}
}

func TestCompatibilityCertificationFabricII0171(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.1", "commit-171")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.1", "commit-171")
	if err != nil {
		t.Fatalf("0.17.1 Fabric Compatibility II evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "fabric-compatibility-II-0.17.1-stable-1.14-through-current-actual-client") {
		t.Fatalf("0.17.1 policy does not bind Fabric Compatibility II: %s", certification.Policy)
	}
	if len(certification.FabricVersions) != len(fabricCompatibilityII0171) {
		t.Fatalf("0.17.1 Fabric coverage=%d, want %d", len(certification.FabricVersions), len(fabricCompatibilityII0171))
	}
	for _, minecraft := range []string{"1.14", "1.17", "1.20.5", "1.21.11", "26.3"} {
		if !slices.Contains(certification.FabricVersions, minecraft) {
			t.Fatalf("0.17.1 Fabric coverage missing %s", minecraft)
		}
	}
}

func TestCompatibilityCertificationFabricII0171RejectsMissingRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.1", "commit-171")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "fabric" && target.Minecraft == "1.14" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.1", "commit-171"); err == nil || !strings.Contains(err.Error(), "Fabric Compatibility II 0.17.1") {
		t.Fatalf("0.17.1 must reject missing Fabric 1.14 target, got %v", err)
	}
}

func TestCompatibilityCertificationFabricII0171RejectsWrongJavaMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.1", "commit-171")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "fabric" && targets.Targets[i].Minecraft == "1.17" {
			targets.Targets[i].JavaMajor = 17
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.1", "commit-171"); err == nil || !strings.Contains(err.Error(), "Fabric 1.17") {
		t.Fatalf("0.17.1 must reject Fabric 1.17 Java mismatch, got %v", err)
	}
}

func TestCompatibilityCertificationFabricII0171RejectsMutableResolvedLoader(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.1", "commit-171")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].Loader == "fabric" && matrix.Targets[i].MinecraftVersion == "1.14" {
			matrix.Targets[i].ResolvedLoaderVersion = "latest-stable"
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.1", "commit-171"); err == nil || !strings.Contains(err.Error(), "immutable version") {
		t.Fatalf("0.17.1 must reject mutable Fabric loader evidence, got %v", err)
	}
}

func TestCompatibilityCertificationQuiltII0172(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.2", "commit-172")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.2", "commit-172")
	if err != nil {
		t.Fatalf("0.17.2 Quilt Compatibility II evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "quilt-compatibility-II-0.17.2-stable-1.14-through-current-actual-client") {
		t.Fatalf("0.17.2 policy does not bind Quilt Compatibility II: %s", certification.Policy)
	}
	if len(certification.QuiltVersions) != len(quiltCompatibilityII0172) {
		t.Fatalf("0.17.2 Quilt coverage=%d, want %d", len(certification.QuiltVersions), len(quiltCompatibilityII0172))
	}
	for _, minecraft := range []string{"1.14", "1.17", "1.20.5", "1.21.11", "26.3"} {
		if !slices.Contains(certification.QuiltVersions, minecraft) {
			t.Fatalf("0.17.2 Quilt coverage missing %s", minecraft)
		}
	}
}

func TestCompatibilityCertificationQuiltII0172RejectsMissingRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.2", "commit-172")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "quilt" && target.Minecraft == "1.14" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.2", "commit-172"); err == nil || !strings.Contains(err.Error(), "Quilt Compatibility II 0.17.2") {
		t.Fatalf("0.17.2 must reject missing Quilt 1.14 target, got %v", err)
	}
}

func TestCompatibilityCertificationQuiltII0172RejectsWrongJavaMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.2", "commit-172")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "quilt" && targets.Targets[i].Minecraft == "1.17" {
			targets.Targets[i].JavaMajor = 17
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.2", "commit-172"); err == nil || !strings.Contains(err.Error(), "Quilt 1.17") {
		t.Fatalf("0.17.2 must reject Quilt 1.17 Java mismatch, got %v", err)
	}
}

func TestCompatibilityCertificationQuiltII0172RejectsMutableResolvedLoader(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.2", "commit-172")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].Loader == "quilt" && matrix.Targets[i].MinecraftVersion == "1.14" {
			matrix.Targets[i].ResolvedLoaderVersion = "latest-stable"
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.2", "commit-172"); err == nil || !strings.Contains(err.Error(), "immutable version") {
		t.Fatalf("0.17.2 must reject mutable Quilt loader evidence, got %v", err)
	}
}

func TestCompatibilityCertificationForgeModern0173(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.3", "commit-173")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.3", "commit-173")
	if err != nil {
		t.Fatalf("0.17.3 Forge Modern evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "forge-modern-0.17.3-processor-based-1.13.2-through-current-actual-client") {
		t.Fatalf("0.17.3 policy does not bind Forge Modern: %s", certification.Policy)
	}
	if len(certification.ForgeVersions) != len(forgeModern0173) {
		t.Fatalf("0.17.3 Forge coverage=%d, want %d", len(certification.ForgeVersions), len(forgeModern0173))
	}
	for _, minecraft := range []string{"1.13.2", "1.17.1", "1.20.6", "1.21.11", "26.3"} {
		if !slices.Contains(certification.ForgeVersions, minecraft) {
			t.Fatalf("0.17.3 Forge coverage missing %s", minecraft)
		}
	}
}

func TestCompatibilityCertificationForgeModern0173RejectsMissingRelease(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.3", "commit-173")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "forge" && target.Minecraft == "1.13.2" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.3", "commit-173"); err == nil || !strings.Contains(err.Error(), "Forge Modern 0.17.3") {
		t.Fatalf("0.17.3 must reject missing Forge 1.13.2 target, got %v", err)
	}
}

func TestCompatibilityCertificationForgeModern0173RejectsWrongJavaMajor(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.3", "commit-173")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "forge" && targets.Targets[i].Minecraft == "1.17.1" {
			targets.Targets[i].JavaMajor = 17
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.3", "commit-173"); err == nil || !strings.Contains(err.Error(), "Forge 1.17.1") {
		t.Fatalf("0.17.3 must reject Forge 1.17.1 Java mismatch, got %v", err)
	}
}

func TestCompatibilityCertificationForgeModern0173BundleRejectsTamperedForgeCoverage(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.3", "commit-173")
	dir := t.TempDir()
	matrixPath := filepath.Join(dir, "matrix.json")
	targetsPath := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetsPath, targetsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedCompatibilityCertification(bundle, matrixPath, targetsPath, "0.17.3", "commit-173"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(bundle, compatibilityCertificationReleaseFile)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	var cert releaseCompatibilityCertification
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	if len(cert.ForgeVersions) < 2 {
		t.Fatalf("expected broad Forge coverage, got %v", cert.ForgeVersions)
	}
	cert.ForgeVersions = cert.ForgeVersions[:len(cert.ForgeVersions)-1]
	raw, err = json.MarshalIndent(cert, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(certPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.17.3"); err == nil {
		t.Fatal("bundle verifier must reject tampered Forge coverage")
	}
}

func TestCompatibilityCertificationForgeModern0173RejectsMutableResolvedLoader(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.3", "commit-173")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].Loader == "forge" && matrix.Targets[i].MinecraftVersion == "1.13.2" {
			matrix.Targets[i].ResolvedLoaderVersion = "latest-stable"
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.3", "commit-173"); err == nil || !strings.Contains(err.Error(), "immutable version") {
		t.Fatalf("0.17.3 must reject mutable Forge loader evidence, got %v", err)
	}
}

func TestCompatibilityCertificationForgeLegacy1122_0174(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.4", "commit-174")
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.4", "commit-174")
	if err != nil {
		t.Fatalf("0.17.4 Forge Legacy evidence must pass: %v", err)
	}
	if !strings.Contains(certification.Policy, "forge-legacy-0.17.4-real-1.12.2-universal-fmltweaker-actual-client") {
		t.Fatalf("0.17.4 policy does not bind Forge Legacy 1.12.2: %s", certification.Policy)
	}
	if !slices.Contains(certification.ForgeVersions, "1.12.2") {
		t.Fatalf("0.17.4 Forge coverage missing 1.12.2: %v", certification.ForgeVersions)
	}
}

func TestCompatibilityCertificationForgeLegacy1122_0174RejectsMissingTarget(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.4", "commit-174")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	filtered := targets.Targets[:0]
	for _, target := range targets.Targets {
		if target.Loader == "forge" && target.Minecraft == "1.12.2" {
			continue
		}
		filtered = append(filtered, target)
	}
	targets.Targets = filtered
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.4", "commit-174"); err == nil || !strings.Contains(err.Error(), "Forge Legacy 1.12.2 0.17.4") {
		t.Fatalf("0.17.4 must reject missing Forge 1.12.2 target, got %v", err)
	}
}

func TestCompatibilityCertificationForgeLegacy1122_0174RejectsMutableResolvedLoader(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.4", "commit-174")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].Loader == "forge" && matrix.Targets[i].MinecraftVersion == "1.12.2" {
			matrix.Targets[i].ResolvedLoaderVersion = "latest-stable"
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.4", "commit-174"); err == nil || !strings.Contains(err.Error(), "immutable version") {
		t.Fatalf("0.17.4 must reject mutable Forge legacy loader evidence, got %v", err)
	}
}

func TestCompatibilityCertificationGA0170RejectsMissingJREAttestation(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.0", "commit-170")
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	for i := range matrix.Targets {
		if matrix.Targets[i].TargetID == "vanilla-1.20.4-linux-x64" {
			matrix.Targets[i].Checks["jreCertified"] = false
			matrix.Targets[i].JREExecutableSHA256 = ""
		}
	}
	matrixRaw, _ = json.Marshal(matrix)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.0", "commit-170"); err == nil {
		t.Fatal("0.17.0 GA must reject missing JRE attestation")
	}
}
