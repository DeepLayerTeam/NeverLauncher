package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	windowsAdversarialCertificateFile01811 = "WINDOWS_ADVERSARIAL_CERTIFICATE.json"
	windowsProtectionReleaseFile01812      = "WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json"
	windowsProtectionReleaseSchema01812    = "1.0"
	windowsProtectionReleaseStatus01812    = "windows-protection-release-candidate"
	windowsProtectionRepository01812       = "DeepLayerTeam/NeverLauncher"
)

var sha256RE01812 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type windowsProtectionArtifact01812 struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type windowsAdversarialCertificate01812 struct {
	SchemaVersion          string   `json:"schemaVersion"`
	Kind                   string   `json:"kind"`
	ProductVersion         string   `json:"productVersion"`
	Repository             string   `json:"repository"`
	Commit                 string   `json:"commit"`
	RunID                  string   `json:"runId"`
	Platform               string   `json:"platform"`
	JavaMajors             []int    `json:"javaMajors"`
	RequiredJavaMajorCount int      `json:"requiredJavaMajorCount"`
	PassedJavaMajorCount   int      `json:"passedJavaMajorCount"`
	ScenarioExecutions     int      `json:"scenarioExecutions"`
	CompatibilityScenarios []string `json:"compatibilityScenarios"`
	AdversarialScenarios   []string `json:"adversarialScenarios"`
	EvidenceRootSHA256     string   `json:"evidenceRootSha256"`
	JavaEvidence           []struct {
		JavaMajor          int    `json:"javaMajor"`
		EvidenceRootSHA256 string `json:"evidenceRootSha256"`
	} `json:"javaEvidence"`
	Invariants map[string]bool `json:"invariants"`
	Policy     string          `json:"policy"`
}

type windowsProtectionReleaseCertificate01812 struct {
	SchemaVersion                 string                           `json:"schemaVersion"`
	Product                       string                           `json:"product"`
	Version                       string                           `json:"version"`
	Status                        string                           `json:"status"`
	ProtectionProfile             string                           `json:"protectionProfile"`
	SourceCommit                  string                           `json:"sourceCommit"`
	Repository                    string                           `json:"repository"`
	AdversarialRunID              string                           `json:"adversarialRunId"`
	CreatedAt                     string                           `json:"createdAt"`
	AdversarialCertificateSHA256  string                           `json:"adversarialCertificateSha256"`
	AdversarialEvidenceRootSHA256 string                           `json:"adversarialEvidenceRootSha256"`
	ScenarioExecutions            int                              `json:"scenarioExecutions"`
	JavaMajors                    []int                            `json:"javaMajors"`
	RequiredCapabilities          []string                         `json:"requiredCapabilities"`
	Artifacts                     []windowsProtectionArtifact01812 `json:"artifacts"`
	BoundarySHA256                string                           `json:"boundarySha256"`
	CertificateID                 string                           `json:"certificateId"`
	Invariants                    map[string]bool                  `json:"invariants"`
}

func windowsProtectionReleaseRequired01812(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 18 || (minor == 18 && patch >= 12)))
}

func expectedWindowsProtectionCapabilities01812() []string {
	return []string{
		"aggressive-protection-profile",
		"signed-early-jvm-sensor",
		"continuous-module-guard",
		"aggressive-hook-engine",
		"executable-memory-integrity",
		"thread-process-integrity",
		"debug-instrumentation-guard",
		"jvm-aware-protection-java-8-16-17-21-25",
		"continuous-sensor-guard-cross-check",
		"continuous-attestation-v2",
		"windows-adversarial-certification-55-executions",
		"authenticode-rfc3161-x64-arm64",
	}
}

func validateWindowsAdversarialCertificate01812(cert windowsAdversarialCertificate01812, ver, expectedCommit string) error {
	commit, err := normalizeSourceCommit01511(expectedCommit)
	if err != nil {
		return err
	}
	if cert.SchemaVersion != "1.0" || cert.Kind != "neverlauncher-windows-adversarial-certification" || cert.ProductVersion != ver {
		return errors.New("Windows adversarial certificate identity mismatch")
	}
	if !strings.EqualFold(cert.Repository, windowsProtectionRepository01812) {
		return fmt.Errorf("Windows adversarial certificate repository mismatch: %q", cert.Repository)
	}
	certCommit, err := normalizeSourceCommit01511(cert.Commit)
	if err != nil || !strings.EqualFold(certCommit, commit) {
		return errors.New("Windows adversarial certificate source commit mismatch")
	}
	if cert.Platform != "windows-x86_64" {
		return fmt.Errorf("Windows adversarial certificate platform mismatch: %q", cert.Platform)
	}
	if _, err := strconv.ParseUint(strings.TrimSpace(cert.RunID), 10, 64); err != nil {
		return fmt.Errorf("Windows adversarial certificate runId invalid: %q", cert.RunID)
	}
	expectedJava := []int{8, 16, 17, 21, 25}
	if len(cert.JavaMajors) != len(expectedJava) || len(cert.JavaEvidence) != len(expectedJava) {
		return errors.New("Windows adversarial certificate Java cohort size mismatch")
	}
	for i, major := range expectedJava {
		if cert.JavaMajors[i] != major || cert.JavaEvidence[i].JavaMajor != major || !sha256RE01812.MatchString(strings.ToLower(cert.JavaEvidence[i].EvidenceRootSHA256)) {
			return fmt.Errorf("Windows adversarial certificate Java %d evidence mismatch", major)
		}
	}
	if cert.RequiredJavaMajorCount != 5 || cert.PassedJavaMajorCount != 5 || cert.ScenarioExecutions != 55 {
		return errors.New("Windows adversarial certificate execution cohort mismatch")
	}
	expectedCompatibility := []string{"sensor-early-load", "trusted-module-lifecycle", "continuous-cross-check", "job-bound-process-tree", "hotspot-jit"}
	expectedAdversarial := []string{"unsigned-module", "code-page-drift", "private-exec-thread", "startup-instrumentation", "live-debugger", "foreign-executable-allocation"}
	if len(cert.CompatibilityScenarios) != len(expectedCompatibility) || len(cert.AdversarialScenarios) != len(expectedAdversarial) {
		return errors.New("Windows adversarial certificate scenario set size mismatch")
	}
	for i := range expectedCompatibility {
		if cert.CompatibilityScenarios[i] != expectedCompatibility[i] {
			return fmt.Errorf("Windows adversarial compatibility scenario #%d mismatch", i+1)
		}
	}
	for i := range expectedAdversarial {
		if cert.AdversarialScenarios[i] != expectedAdversarial[i] {
			return fmt.Errorf("Windows adversarial scenario #%d mismatch", i+1)
		}
	}
	if !sha256RE01812.MatchString(strings.ToLower(cert.EvidenceRootSHA256)) {
		return errors.New("Windows adversarial certificate evidence root invalid")
	}
	rootMaterial := make([]map[string]any, 0, len(cert.JavaEvidence))
	for _, row := range cert.JavaEvidence {
		rootMaterial = append(rootMaterial, map[string]any{"javaMajor": row.JavaMajor, "evidenceRootSha256": row.EvidenceRootSHA256})
	}
	canonical, err := json.Marshal(rootMaterial)
	if err != nil {
		return err
	}
	rootDigest := sha256.Sum256(canonical)
	if !strings.EqualFold(hex.EncodeToString(rootDigest[:]), cert.EvidenceRootSHA256) {
		return errors.New("Windows adversarial certificate aggregate evidence root mismatch")
	}
	for _, key := range []string{
		"allCertifiedJavaMajorsPassed", "allCompatibilityScenariosPassed", "allAdversarialScenariosDetected",
		"sensorGuardContinuousCrossCheckPassed", "failClosedAttackBoundaryPassed", "exactScenarioSetBound", "sensorAndFixtureHashesBound",
	} {
		if !cert.Invariants[key] {
			return fmt.Errorf("Windows adversarial certificate invariant %s is not satisfied", key)
		}
	}
	if cert.Policy != "windows-adversarial-ci-0.18.11-live-jvm-attack-simulation-and-java-compatibility-certification" {
		return fmt.Errorf("Windows adversarial certificate policy mismatch: %q", cert.Policy)
	}
	return nil
}

func readWindowsAdversarialCertificate01812(dir, ver, expectedCommit string) (windowsAdversarialCertificate01812, string, error) {
	path := filepath.Join(dir, windowsAdversarialCertificateFile01811)
	raw, err := os.ReadFile(path)
	if err != nil {
		return windowsAdversarialCertificate01812{}, "", fmt.Errorf("read %s: %w", windowsAdversarialCertificateFile01811, err)
	}
	var cert windowsAdversarialCertificate01812
	if err := json.Unmarshal(raw, &cert); err != nil {
		return cert, "", fmt.Errorf("invalid %s: %w", windowsAdversarialCertificateFile01811, err)
	}
	if err := validateWindowsAdversarialCertificate01812(cert, ver, expectedCommit); err != nil {
		return cert, "", err
	}
	sum, _, err := hashFile(path)
	return cert, strings.ToLower(sum), err
}

func windowsProtectionArtifactNames01812(ver string) []string {
	names := []string{
		windowsAdversarialCertificateFile01811,
		windowsSigningEvidenceFile0152,
		windowsDeliveryAllowlistFile0152,
		"WINDOWS_PACKAGE_MANIFEST_X64.json",
		"WINDOWS_PACKAGE_MANIFEST_ARM64.json",
		"neverlauncher-desktop-" + ver + "-windows-x64.zip",
		"neverlauncher-desktop-" + ver + "-windows-arm64.zip",
	}
	for _, arch := range []string{"x64", "arm64"} {
		artifacts := expectedWindowsSignedArtifactsForVersion0157(ver, arch)
		components := make([]string, 0, len(artifacts))
		for component := range artifacts {
			components = append(components, component)
		}
		sort.Strings(components)
		for _, component := range components {
			names = append(names, artifacts[component])
		}
	}
	sort.Strings(names)
	return names
}

func windowsProtectionArtifacts01812(dir, ver string) ([]windowsProtectionArtifact01812, error) {
	names := windowsProtectionArtifactNames01812(ver)
	rows := make([]windowsProtectionArtifact01812, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		clean, err := safeReleaseRelativePath0158(name)
		if err != nil || clean != name {
			return nil, fmt.Errorf("Windows protection artifact path invalid: %q", name)
		}
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("Windows protection artifact %s: %w", name, err)
		}
		if size <= 0 || !sha256RE01812.MatchString(strings.ToLower(sum)) {
			return nil, fmt.Errorf("Windows protection artifact %s is empty or has invalid SHA-256", name)
		}
		rows = append(rows, windowsProtectionArtifact01812{Name: name, Size: size, SHA256: strings.ToLower(sum)})
	}
	return rows, nil
}

func windowsProtectionBoundaryDigest01812(ver, commit, repository, runID, adversarialRoot string, artifacts []windowsProtectionArtifact01812, capabilities []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "NeverLauncher Windows Protection RC\n%s\n%s\n%s\n%s\n%s\naggressive\n", ver, strings.ToLower(commit), repository, runID, strings.ToLower(adversarialRoot))
	for _, capability := range capabilities {
		fmt.Fprintf(h, "capability %s\n", capability)
	}
	for _, item := range artifacts {
		fmt.Fprintf(h, "%s  %d  %s\n", strings.ToLower(item.SHA256), item.Size, item.Name)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func buildWindowsProtectionReleaseDocument01812(dir, ver, expectedCommit string) (windowsProtectionReleaseCertificate01812, error) {
	if !windowsProtectionReleaseRequired01812(ver) {
		return windowsProtectionReleaseCertificate01812{}, fmt.Errorf("Windows Protection RC requires 0.18.12+, got %s", ver)
	}
	commit, err := normalizeSourceCommit01511(expectedCommit)
	if err != nil {
		return windowsProtectionReleaseCertificate01812{}, err
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, true); err != nil {
		return windowsProtectionReleaseCertificate01812{}, fmt.Errorf("Windows Authenticode production boundary: %w", err)
	}
	adversarial, adversarialHash, err := readWindowsAdversarialCertificate01812(dir, ver, commit)
	if err != nil {
		return windowsProtectionReleaseCertificate01812{}, err
	}
	artifacts, err := windowsProtectionArtifacts01812(dir, ver)
	if err != nil {
		return windowsProtectionReleaseCertificate01812{}, err
	}
	capabilities := expectedWindowsProtectionCapabilities01812()
	boundary := windowsProtectionBoundaryDigest01812(ver, commit, adversarial.Repository, adversarial.RunID, adversarial.EvidenceRootSHA256, artifacts, capabilities)
	invariants := map[string]bool{
		"aggressiveProfileRequired":            true,
		"sensorEarlyLoadCertified":             true,
		"continuousModuleGuardCertified":       true,
		"aggressiveHookEngineCertified":        true,
		"memoryIntegrityCertified":             true,
		"threadProcessIntegrityCertified":      true,
		"debugInstrumentationGuardCertified":   true,
		"jvmAwareJavaCohortCertified":          true,
		"continuousGuardCrossCheckCertified":   true,
		"continuousAttestationV2Certified":     true,
		"adversarialAttackSimulationCertified": true,
		"x64Arm64AuthenticodeCertified":        true,
		"publishedWindowsBytesBound":           true,
	}
	return windowsProtectionReleaseCertificate01812{
		SchemaVersion: windowsProtectionReleaseSchema01812, Product: "NeverLauncher", Version: ver,
		Status: windowsProtectionReleaseStatus01812, ProtectionProfile: "aggressive", SourceCommit: commit,
		Repository: adversarial.Repository, AdversarialRunID: adversarial.RunID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		AdversarialCertificateSHA256: adversarialHash, AdversarialEvidenceRootSHA256: strings.ToLower(adversarial.EvidenceRootSHA256),
		ScenarioExecutions: adversarial.ScenarioExecutions, JavaMajors: append([]int(nil), adversarial.JavaMajors...),
		RequiredCapabilities: capabilities, Artifacts: artifacts, BoundarySHA256: boundary, CertificateID: "sha256:" + boundary,
		Invariants: invariants,
	}, nil
}

func writeWindowsProtectionRelease01812(dir, ver, expectedCommit string) error {
	if !windowsProtectionReleaseRequired01812(ver) {
		return nil
	}
	cert, err := buildWindowsProtectionReleaseDocument01812(dir, ver, expectedCommit)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, windowsProtectionReleaseFile01812), cert)
}

func verifyWindowsProtectionRelease01812(dir, ver string) error {
	if !windowsProtectionReleaseRequired01812(ver) {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, windowsProtectionReleaseFile01812))
	if err != nil {
		return fmt.Errorf("read %s: %w", windowsProtectionReleaseFile01812, err)
	}
	var cert windowsProtectionReleaseCertificate01812
	if err := json.Unmarshal(raw, &cert); err != nil {
		return fmt.Errorf("invalid %s: %w", windowsProtectionReleaseFile01812, err)
	}
	commit, err := normalizeSourceCommit01511(cert.SourceCommit)
	if err != nil {
		return err
	}
	expected, err := buildWindowsProtectionReleaseDocument01812(dir, ver, commit)
	if err != nil {
		return err
	}
	if cert.SchemaVersion != expected.SchemaVersion || cert.Product != expected.Product || cert.Version != expected.Version || cert.Status != expected.Status || cert.ProtectionProfile != "aggressive" {
		return errors.New("Windows Protection RC metadata mismatch")
	}
	if !strings.EqualFold(cert.SourceCommit, expected.SourceCommit) || !strings.EqualFold(cert.Repository, expected.Repository) || cert.AdversarialRunID != expected.AdversarialRunID {
		return errors.New("Windows Protection RC source/repository/run binding mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, cert.CreatedAt); err != nil {
		return fmt.Errorf("Windows Protection RC createdAt invalid: %w", err)
	}
	if !strings.EqualFold(cert.AdversarialCertificateSHA256, expected.AdversarialCertificateSHA256) || !strings.EqualFold(cert.AdversarialEvidenceRootSHA256, expected.AdversarialEvidenceRootSHA256) {
		return errors.New("Windows Protection RC adversarial evidence binding mismatch")
	}
	if cert.ScenarioExecutions != 55 || len(cert.JavaMajors) != len(expected.JavaMajors) {
		return errors.New("Windows Protection RC Java/adversarial cohort mismatch")
	}
	for i := range expected.JavaMajors {
		if cert.JavaMajors[i] != expected.JavaMajors[i] {
			return fmt.Errorf("Windows Protection RC Java major #%d mismatch", i+1)
		}
	}
	if len(cert.RequiredCapabilities) != len(expected.RequiredCapabilities) || len(cert.Artifacts) != len(expected.Artifacts) {
		return errors.New("Windows Protection RC capability/artifact cohort size mismatch")
	}
	for i := range expected.RequiredCapabilities {
		if cert.RequiredCapabilities[i] != expected.RequiredCapabilities[i] {
			return fmt.Errorf("Windows Protection RC capability #%d mismatch", i+1)
		}
	}
	for i := range expected.Artifacts {
		a, b := cert.Artifacts[i], expected.Artifacts[i]
		if a.Name != b.Name || a.Size != b.Size || !strings.EqualFold(a.SHA256, b.SHA256) {
			return fmt.Errorf("Windows Protection RC artifact mismatch: %s", b.Name)
		}
	}
	for key, value := range expected.Invariants {
		if !value || !cert.Invariants[key] {
			return fmt.Errorf("Windows Protection RC invariant %s is not satisfied", key)
		}
	}
	if !strings.EqualFold(cert.BoundarySHA256, expected.BoundarySHA256) || cert.CertificateID != "sha256:"+strings.ToLower(expected.BoundarySHA256) {
		return errors.New("Windows Protection RC boundary/certificateId mismatch")
	}
	return nil
}
