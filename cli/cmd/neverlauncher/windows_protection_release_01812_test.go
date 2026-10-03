package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func syntheticWindowsAdversarialCertificate01812() windowsAdversarialCertificate01812 {
	roots := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)}
	cert := windowsAdversarialCertificate01812{
		SchemaVersion: "1.0", Kind: "neverlauncher-windows-adversarial-certification", ProductVersion: "0.18.12",
		Repository: windowsProtectionRepository01812, Commit: testSourceCommit01511, RunID: "123456", Platform: "windows-x86_64",
		JavaMajors: []int{8, 16, 17, 21, 25}, RequiredJavaMajorCount: 5, PassedJavaMajorCount: 5,
		ScenarioExecutions:     55,
		CompatibilityScenarios: []string{"sensor-early-load", "trusted-module-lifecycle", "continuous-cross-check", "job-bound-process-tree", "hotspot-jit"},
		AdversarialScenarios:   []string{"unsigned-module", "code-page-drift", "private-exec-thread", "startup-instrumentation", "live-debugger", "foreign-executable-allocation"},
		Invariants: map[string]bool{
			"allCertifiedJavaMajorsPassed": true, "allCompatibilityScenariosPassed": true, "allAdversarialScenariosDetected": true,
			"sensorGuardContinuousCrossCheckPassed": true, "failClosedAttackBoundaryPassed": true, "exactScenarioSetBound": true, "sensorAndFixtureHashesBound": true,
		},
		Policy: "windows-adversarial-ci-0.18.11-live-jvm-attack-simulation-and-java-compatibility-certification",
	}
	for i, major := range cert.JavaMajors {
		cert.JavaEvidence = append(cert.JavaEvidence, struct {
			JavaMajor          int    `json:"javaMajor"`
			EvidenceRootSHA256 string `json:"evidenceRootSha256"`
		}{JavaMajor: major, EvidenceRootSHA256: roots[i]})
	}
	material := make([]map[string]any, 0, len(cert.JavaEvidence))
	for _, row := range cert.JavaEvidence {
		material = append(material, map[string]any{"javaMajor": row.JavaMajor, "evidenceRootSha256": row.EvidenceRootSHA256})
	}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	cert.EvidenceRootSHA256 = hex.EncodeToString(sum[:])
	return cert
}

func TestWindowsProtectionReleaseRequired01812(t *testing.T) {
	if windowsProtectionReleaseRequired01812("0.18.11") || !windowsProtectionReleaseRequired01812("0.18.12") || !windowsProtectionReleaseRequired01812("0.19.0") {
		t.Fatal("Windows Protection RC version gate mismatch")
	}
}

func TestValidateWindowsAdversarialCertificate01812(t *testing.T) {
	cert := syntheticWindowsAdversarialCertificate01812()
	if err := validateWindowsAdversarialCertificate01812(cert, "0.18.12", testSourceCommit01511); err != nil {
		t.Fatalf("valid adversarial certificate rejected: %v", err)
	}
	cert.ScenarioExecutions = 54
	if err := validateWindowsAdversarialCertificate01812(cert, "0.18.12", testSourceCommit01511); err == nil {
		t.Fatal("incomplete adversarial execution cohort accepted")
	}
}

func TestWindowsProtectionBoundaryDigest01812BindsArtifactsAndCapabilities(t *testing.T) {
	artifacts := []windowsProtectionArtifact01812{{Name: "neverguard.exe", Size: 7, SHA256: strings.Repeat("1", 64)}}
	capabilities := []string{"aggressive-protection-profile", "continuous-attestation-v2"}
	first := windowsProtectionBoundaryDigest01812("0.18.12", testSourceCommit01511, windowsProtectionRepository01812, "42", strings.Repeat("2", 64), artifacts, capabilities)
	second := windowsProtectionBoundaryDigest01812("0.18.12", testSourceCommit01511, windowsProtectionRepository01812, "42", strings.Repeat("2", 64), []windowsProtectionArtifact01812{{Name: "neverguard.exe", Size: 8, SHA256: strings.Repeat("1", 64)}}, capabilities)
	if first == second || len(first) != 64 {
		t.Fatal("Windows Protection RC boundary does not bind artifact size")
	}
}
