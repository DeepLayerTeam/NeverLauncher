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
	"strings"
	"time"
)

const productionReleaseCandidateFile01511 = "PRODUCTION_RELEASE_CANDIDATE.json"

var sourceCommitRE01511 = regexp.MustCompile(`^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$`)

type productionReleaseCandidateArtifact01511 struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type productionReleaseCandidate01511 struct {
	SchemaVersion string                                    `json:"schemaVersion"`
	Product       string                                    `json:"product"`
	Version       string                                    `json:"version"`
	Status        string                                    `json:"status"`
	SourceCommit  string                                    `json:"sourceCommit"`
	CreatedAt     string                                    `json:"createdAt"`
	CohortSHA256  string                                    `json:"cohortSha256"`
	Cohort        []productionReleaseCandidateArtifact01511 `json:"cohort"`
	RequiredGates []string                                  `json:"requiredGates"`
}

func productionReleaseCandidateRequired01511(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && (minor > 15 || (minor == 15 && patch >= 11)))
}

func productionReleaseCandidateRequiredGates01511() []string {
	return []string{
		"minecraft-compatibility-certification",
		"device-trust-certification",
		"cross-platform-guard-ci-certification",
		"serverbridge2-certification",
		"windows-x64-arm64-authenticode-rfc3161",
		"linux-x64-arm64-production-packages",
		"macos-x64-arm64-developer-id-notarization",
		"managed-jre-temurin21-six-target-distribution",
		"unified-transactional-updater-core",
		"desktop-guard-runtime-transactional-update",
		"release-verification-v2-trust-lifecycle",
		"public-production-delivery-matrix-six-target-e2e",
		"migration-stabilization-0.15.10",
		"exact-source-commit-cohort",
	}
}

func normalizeSourceCommit01511(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !sourceCommitRE01511.MatchString(value) {
		return "", fmt.Errorf("production release candidate requires exact 40/64-hex source commit, got %q", value)
	}
	return value, nil
}

func releaseCandidateExcludedFile01511(name string) bool {
	switch name {
	case productionReleaseCandidateFile01511, "RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "PROVENANCE.json.sig":
		return true
	default:
		return false
	}
}

func productionReleaseCandidateCohort01511(dir string) ([]productionReleaseCandidateArtifact01511, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	cohort := make([]productionReleaseCandidateArtifact01511, 0, len(items))
	for _, item := range items {
		name := item.Name()
		if item.IsDir() || releaseCandidateExcludedFile01511(name) {
			continue
		}
		clean, err := safeReleaseRelativePath0158(name)
		if err != nil || clean != name {
			return nil, fmt.Errorf("release candidate cohort path %q invalid", name)
		}
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("hash release candidate cohort %s: %w", name, err)
		}
		cohort = append(cohort, productionReleaseCandidateArtifact01511{Name: name, Size: size, SHA256: strings.ToLower(sum)})
	}
	sort.Slice(cohort, func(i, j int) bool { return cohort[i].Name < cohort[j].Name })
	return cohort, nil
}

func productionReleaseCandidateCohortDigest01511(cohort []productionReleaseCandidateArtifact01511) string {
	h := sha256.New()
	for _, item := range cohort {
		fmt.Fprintf(h, "%s  %d  %s\n", strings.ToLower(item.SHA256), item.Size, item.Name)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readCertificationCommit01511(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload struct {
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	return normalizeSourceCommit01511(payload.Commit)
}

func provenanceSourceCommit01511(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					Version      string `json:"version"`
					SourceCommit string `json:"sourceCommit"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("invalid PROVENANCE.json: %w", err)
	}
	return normalizeSourceCommit01511(payload.Predicate.BuildDefinition.ExternalParameters.SourceCommit)
}

func verifyProductionReleaseCandidatePrerequisites01511(dir, ver, sourceCommit string, strict bool) error {
	commit, err := normalizeSourceCommit01511(sourceCommit)
	if err != nil {
		return err
	}
	for _, file := range []string{compatibilityCertificationReleaseFile, deviceTrustCertificationReleaseFile, guardCICertificationReleaseFile} {
		certCommit, err := readCertificationCommit01511(filepath.Join(dir, file))
		if err != nil {
			return fmt.Errorf("production release candidate requires %s with exact source commit: %w", file, err)
		}
		if !strings.EqualFold(certCommit, commit) {
			return fmt.Errorf("%s source commit mismatch: candidate=%s certification=%s", file, commit, certCommit)
		}
	}
	provCommit, err := provenanceSourceCommit01511(filepath.Join(dir, "PROVENANCE.json"))
	if err != nil {
		return fmt.Errorf("production provenance source commit: %w", err)
	}
	if !strings.EqualFold(provCommit, commit) {
		return fmt.Errorf("PROVENANCE.json sourceCommit mismatch: candidate=%s provenance=%s", commit, provCommit)
	}
	if err := verifyCompatibilityCertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Minecraft Compatibility certification: %w", err)
	}
	if err := verifyDeviceTrustCertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Device Trust certification: %w", err)
	}
	if err := verifyGuardCICertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Cross-platform Guard CI certification: %w", err)
	}
	if err := verifyServerBridge2CertificationInBundle0150(dir, ver); err != nil {
		return fmt.Errorf("ServerBridge 2 certification: %w", err)
	}
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		return fmt.Errorf("Delivery Manifest: %w", err)
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, strict); err != nil {
		return fmt.Errorf("Windows production signing: %w", err)
	}
	if err := verifyLinuxProductionEvidence0153(dir, ver, true); err != nil {
		return fmt.Errorf("Linux production packages: %w", err)
	}
	if err := verifyMacOSNotarizationEvidence0154(dir, ver, strict); err != nil {
		return fmt.Errorf("macOS production notarization: %w", err)
	}
	if err := verifyManagedJREDistribution0155(dir, ver, true); err != nil {
		return fmt.Errorf("Managed JRE Distribution: %w", err)
	}
	if err := verifyPublicProductionDeliveryMatrix0159(dir, ver); err != nil {
		return fmt.Errorf("Public Production Delivery Matrix: %w", err)
	}
	if _, err := loadReleaseTrustPolicy0158(filepath.Join(dir, releaseTrustPolicyFile0158)); err != nil {
		return fmt.Errorf("Release Verification v2 trust policy: %w", err)
	}
	return nil
}

func writeProductionReleaseCandidateDocument01511(dir, ver, sourceCommit string) error {
	commit, err := normalizeSourceCommit01511(sourceCommit)
	if err != nil {
		return err
	}
	cohort, err := productionReleaseCandidateCohort01511(dir)
	if err != nil {
		return err
	}
	if len(cohort) == 0 {
		return errors.New("production release candidate cohort is empty")
	}
	cert := productionReleaseCandidate01511{
		SchemaVersion: "1.0",
		Product:       "NeverLauncher",
		Version:       ver,
		Status:        "production-release-candidate",
		SourceCommit:  commit,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		CohortSHA256:  productionReleaseCandidateCohortDigest01511(cohort),
		Cohort:        cohort,
		RequiredGates: productionReleaseCandidateRequiredGates01511(),
	}
	return writeJSONFile(filepath.Join(dir, productionReleaseCandidateFile01511), cert)
}

func writeProductionReleaseCandidate01511(dir, ver, sourceCommit string, strict bool) error {
	if !productionReleaseCandidateRequired01511(ver) {
		return nil
	}
	commit, err := normalizeSourceCommit01511(sourceCommit)
	if err != nil {
		return err
	}
	if err := verifyProductionReleaseCandidatePrerequisites01511(dir, ver, commit, strict); err != nil {
		return err
	}
	return writeProductionReleaseCandidateDocument01511(dir, ver, commit)
}

func verifyProductionReleaseCandidateDocument01511(dir, ver string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, productionReleaseCandidateFile01511))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", productionReleaseCandidateFile01511, err)
	}
	var cert productionReleaseCandidate01511
	if err := json.Unmarshal(raw, &cert); err != nil {
		return "", fmt.Errorf("invalid %s: %w", productionReleaseCandidateFile01511, err)
	}
	commit, err := normalizeSourceCommit01511(cert.SourceCommit)
	if err != nil {
		return "", err
	}
	if cert.SchemaVersion != "1.0" || cert.Product != "NeverLauncher" || cert.Version != ver || cert.Status != "production-release-candidate" {
		return "", errors.New("production release candidate metadata mismatch")
	}
	if _, err := time.Parse(time.RFC3339, cert.CreatedAt); err != nil {
		return "", fmt.Errorf("production release candidate createdAt invalid: %w", err)
	}
	expectedGates := productionReleaseCandidateRequiredGates01511()
	if len(cert.RequiredGates) != len(expectedGates) {
		return "", errors.New("production release candidate required gate set mismatch")
	}
	for i := range expectedGates {
		if cert.RequiredGates[i] != expectedGates[i] {
			return "", fmt.Errorf("production release candidate gate #%d mismatch: expected=%s actual=%s", i+1, expectedGates[i], cert.RequiredGates[i])
		}
	}
	actualCohort, err := productionReleaseCandidateCohort01511(dir)
	if err != nil {
		return "", err
	}
	if len(actualCohort) != len(cert.Cohort) {
		return "", fmt.Errorf("production release candidate cohort size mismatch: certified=%d actual=%d", len(cert.Cohort), len(actualCohort))
	}
	for i := range actualCohort {
		a, c := actualCohort[i], cert.Cohort[i]
		if a.Name != c.Name || a.Size != c.Size || !strings.EqualFold(a.SHA256, c.SHA256) {
			return "", fmt.Errorf("production release candidate cohort mismatch at %s", a.Name)
		}
	}
	digest := productionReleaseCandidateCohortDigest01511(actualCohort)
	if !strings.EqualFold(digest, strings.TrimSpace(cert.CohortSHA256)) {
		return "", errors.New("production release candidate cohortSha256 mismatch")
	}
	return commit, nil
}

func verifyProductionReleaseCandidate01511(dir, ver string, strict bool) error {
	if !productionReleaseCandidateRequired01511(ver) {
		return nil
	}
	commit, err := verifyProductionReleaseCandidateDocument01511(dir, ver)
	if err != nil {
		return err
	}
	return verifyProductionReleaseCandidatePrerequisites01511(dir, ver, commit, strict)
}
