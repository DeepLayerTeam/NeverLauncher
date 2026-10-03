package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	windowsProtectionGAFile0190        = "WINDOWS_PROTECTION_GA_CERTIFICATE.json"
	windowsProtectionGASchema0190      = "1.0"
	windowsProtectionGAStatus0190      = "windows-protection-ga"
	windowsProtectionGAStage0190       = "ga"
	windowsProtectionGAModel0190       = "user-mode"
	windowsProtectionGAEnforcement0190 = "fail-closed"
)

type windowsProtectionGACertificate0190 struct {
	SchemaVersion                 string                           `json:"schemaVersion"`
	Product                       string                           `json:"product"`
	Version                       string                           `json:"version"`
	Status                        string                           `json:"status"`
	ReleaseStage                  string                           `json:"releaseStage"`
	ProtectionModel               string                           `json:"protectionModel"`
	ProtectionProfile             string                           `json:"protectionProfile"`
	EnforcementMode               string                           `json:"enforcementMode"`
	SourceCommit                  string                           `json:"sourceCommit"`
	Repository                    string                           `json:"repository"`
	CreatedAt                     string                           `json:"createdAt"`
	RCCertificateSHA256           string                           `json:"rcCertificateSha256"`
	RCBoundarySHA256              string                           `json:"rcBoundarySha256"`
	RCCertificateID               string                           `json:"rcCertificateId"`
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

func windowsProtectionGARequired0190(ver string) bool {
	major, minor, _, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && minor >= 19)
}

func windowsProtectionGAStableVersion0190(ver string) error {
	if !windowsProtectionGARequired0190(ver) {
		return fmt.Errorf("Windows Protection GA requires 0.19.0+, got %s", ver)
	}
	if strings.ContainsAny(strings.TrimSpace(ver), "-+") {
		return fmt.Errorf("Windows Protection GA requires stable immutable SemVer without prerelease/build suffix: %q", ver)
	}
	return nil
}

func expectedWindowsProtectionGACapabilities0190() []string {
	capabilities := append([]string(nil), expectedWindowsProtectionCapabilities01812()...)
	capabilities = append(capabilities,
		"production-ga-user-mode-boundary",
		"fail-closed-runtime-enforcement",
		"server-enforced-continuous-attestation-v2-join-ticket",
		"kernel-driver-free-production-package",
	)
	return capabilities
}

func readWindowsProtectionRCCertificate0190(dir, ver string) (windowsProtectionReleaseCertificate01812, string, error) {
	if err := verifyWindowsProtectionRelease01812(dir, ver); err != nil {
		return windowsProtectionReleaseCertificate01812{}, "", fmt.Errorf("Windows Protection RC prerequisite: %w", err)
	}
	path := filepath.Join(dir, windowsProtectionReleaseFile01812)
	raw, err := os.ReadFile(path)
	if err != nil {
		return windowsProtectionReleaseCertificate01812{}, "", err
	}
	var cert windowsProtectionReleaseCertificate01812
	if err := json.Unmarshal(raw, &cert); err != nil {
		return cert, "", fmt.Errorf("invalid %s: %w", windowsProtectionReleaseFile01812, err)
	}
	sum, _, err := hashFile(path)
	return cert, strings.ToLower(sum), err
}

func verifyWindowsUserModeOnlyPackages0190(dir, ver string) error {
	for _, arch := range []string{"x64", "arm64"} {
		packageName, manifestName := expectedWindowsPackage0152(ver, arch)
		manifestRaw, err := os.ReadFile(filepath.Join(dir, manifestName))
		if err != nil {
			return fmt.Errorf("Windows Protection GA read %s: %w", manifestName, err)
		}
		var manifest struct {
			Artifacts []struct {
				Name      string `json:"name"`
				Component string `json:"component"`
			} `json:"artifacts"`
		}
		if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
			return fmt.Errorf("Windows Protection GA invalid %s: %w", manifestName, err)
		}
		for _, artifact := range manifest.Artifacts {
			lower := strings.ToLower(strings.TrimSpace(artifact.Name))
			if strings.HasSuffix(lower, ".sys") || strings.Contains(strings.ToLower(artifact.Component), "driver") {
				return fmt.Errorf("Windows Protection GA rejects kernel-driver artifact in %s: %s", manifestName, artifact.Name)
			}
		}

		packagePath := filepath.Join(dir, packageName)
		archive, err := zip.OpenReader(packagePath)
		if err != nil {
			return fmt.Errorf("Windows Protection GA open %s: %w", packageName, err)
		}
		for _, entry := range archive.File {
			clean := strings.ToLower(filepath.ToSlash(filepath.Clean(entry.Name)))
			if strings.HasSuffix(clean, ".sys") {
				_ = archive.Close()
				return fmt.Errorf("Windows Protection GA rejects kernel-driver payload in %s: %s", packageName, entry.Name)
			}
		}
		if err := archive.Close(); err != nil {
			return fmt.Errorf("Windows Protection GA close %s: %w", packageName, err)
		}
	}
	return nil
}

func windowsProtectionGABoundaryDigest0190(ver, commit, repository, rcHash, rcBoundary, adversarialHash, adversarialRoot string, artifacts []windowsProtectionArtifact01812, capabilities []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "NeverLauncher Windows Protection GA\n%s\n%s\n%s\n%s\n%s\n%s\n%s\nuser-mode\naggressive\nfail-closed\n", ver, strings.ToLower(commit), repository, strings.ToLower(rcHash), strings.ToLower(rcBoundary), strings.ToLower(adversarialHash), strings.ToLower(adversarialRoot))
	for _, capability := range capabilities {
		fmt.Fprintf(h, "capability %s\n", capability)
	}
	for _, item := range artifacts {
		fmt.Fprintf(h, "%s  %d  %s\n", strings.ToLower(item.SHA256), item.Size, item.Name)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func buildWindowsProtectionGADocument0190(dir, ver string) (windowsProtectionGACertificate0190, error) {
	if err := windowsProtectionGAStableVersion0190(ver); err != nil {
		return windowsProtectionGACertificate0190{}, err
	}
	rc, rcHash, err := readWindowsProtectionRCCertificate0190(dir, ver)
	if err != nil {
		return windowsProtectionGACertificate0190{}, err
	}
	if rc.Status != windowsProtectionReleaseStatus01812 || rc.ProtectionProfile != "aggressive" || rc.ScenarioExecutions != 55 {
		return windowsProtectionGACertificate0190{}, errors.New("Windows Protection GA requires a complete aggressive RC certificate")
	}
	if err := verifyWindowsUserModeOnlyPackages0190(dir, ver); err != nil {
		return windowsProtectionGACertificate0190{}, err
	}
	if len(rc.JavaMajors) != 5 {
		return windowsProtectionGACertificate0190{}, errors.New("Windows Protection GA Java cohort incomplete")
	}
	expectedJava := []int{8, 16, 17, 21, 25}
	for i, major := range expectedJava {
		if rc.JavaMajors[i] != major {
			return windowsProtectionGACertificate0190{}, fmt.Errorf("Windows Protection GA Java cohort mismatch at index %d", i)
		}
	}
	artifacts := append([]windowsProtectionArtifact01812(nil), rc.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	capabilities := expectedWindowsProtectionGACapabilities0190()
	boundary := windowsProtectionGABoundaryDigest0190(ver, rc.SourceCommit, rc.Repository, rcHash, rc.BoundarySHA256, rc.AdversarialCertificateSHA256, rc.AdversarialEvidenceRootSHA256, artifacts, capabilities)
	invariants := map[string]bool{
		"rcCertificateVerified":                   true,
		"exactPublishedWindowsBytesBound":         true,
		"aggressiveProfileProductionEnforced":     true,
		"failClosedRuntimeEnforced":               true,
		"continuousSensorGuardCrossCheckRequired": true,
		"continuousAttestationV2Required":         true,
		"oneTimeServerJoinTicketRequired":         true,
		"java8_16_17_21_25Certified":              true,
		"adversarial55ExecutionCohortVerified":    true,
		"x64Arm64AuthenticodeRFC3161Verified":     true,
		"kernelDriverAbsent":                      true,
		"userModeProtectionBoundary":              true,
	}
	return windowsProtectionGACertificate0190{
		SchemaVersion:                 windowsProtectionGASchema0190,
		Product:                       "NeverLauncher",
		Version:                       ver,
		Status:                        windowsProtectionGAStatus0190,
		ReleaseStage:                  windowsProtectionGAStage0190,
		ProtectionModel:               windowsProtectionGAModel0190,
		ProtectionProfile:             "aggressive",
		EnforcementMode:               windowsProtectionGAEnforcement0190,
		SourceCommit:                  strings.ToLower(rc.SourceCommit),
		Repository:                    rc.Repository,
		CreatedAt:                     time.Now().UTC().Format(time.RFC3339Nano),
		RCCertificateSHA256:           rcHash,
		RCBoundarySHA256:              strings.ToLower(rc.BoundarySHA256),
		RCCertificateID:               rc.CertificateID,
		AdversarialCertificateSHA256:  strings.ToLower(rc.AdversarialCertificateSHA256),
		AdversarialEvidenceRootSHA256: strings.ToLower(rc.AdversarialEvidenceRootSHA256),
		ScenarioExecutions:            rc.ScenarioExecutions,
		JavaMajors:                    append([]int(nil), rc.JavaMajors...),
		RequiredCapabilities:          capabilities,
		Artifacts:                     artifacts,
		BoundarySHA256:                boundary,
		CertificateID:                 "sha256:" + boundary,
		Invariants:                    invariants,
	}, nil
}

func writeWindowsProtectionGA0190(dir, ver string) error {
	if !windowsProtectionGARequired0190(ver) {
		return nil
	}
	cert, err := buildWindowsProtectionGADocument0190(dir, ver)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, windowsProtectionGAFile0190), cert)
}

func verifyWindowsProtectionGA0190(dir, ver string) error {
	if !windowsProtectionGARequired0190(ver) {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, windowsProtectionGAFile0190))
	if err != nil {
		return fmt.Errorf("read %s: %w", windowsProtectionGAFile0190, err)
	}
	var cert windowsProtectionGACertificate0190
	if err := json.Unmarshal(raw, &cert); err != nil {
		return fmt.Errorf("invalid %s: %w", windowsProtectionGAFile0190, err)
	}
	expected, err := buildWindowsProtectionGADocument0190(dir, ver)
	if err != nil {
		return err
	}
	if cert.SchemaVersion != expected.SchemaVersion || cert.Product != expected.Product || cert.Version != expected.Version || cert.Status != windowsProtectionGAStatus0190 || cert.ReleaseStage != windowsProtectionGAStage0190 || cert.ProtectionModel != windowsProtectionGAModel0190 || cert.ProtectionProfile != "aggressive" || cert.EnforcementMode != windowsProtectionGAEnforcement0190 {
		return errors.New("Windows Protection GA metadata mismatch")
	}
	if !strings.EqualFold(cert.SourceCommit, expected.SourceCommit) || !strings.EqualFold(cert.Repository, expected.Repository) || !strings.EqualFold(cert.RCCertificateSHA256, expected.RCCertificateSHA256) || !strings.EqualFold(cert.RCBoundarySHA256, expected.RCBoundarySHA256) || cert.RCCertificateID != expected.RCCertificateID {
		return errors.New("Windows Protection GA RC/source binding mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, cert.CreatedAt); err != nil {
		return fmt.Errorf("Windows Protection GA createdAt invalid: %w", err)
	}
	if !strings.EqualFold(cert.AdversarialCertificateSHA256, expected.AdversarialCertificateSHA256) || !strings.EqualFold(cert.AdversarialEvidenceRootSHA256, expected.AdversarialEvidenceRootSHA256) || cert.ScenarioExecutions != 55 {
		return errors.New("Windows Protection GA adversarial evidence mismatch")
	}
	if len(cert.JavaMajors) != len(expected.JavaMajors) || len(cert.RequiredCapabilities) != len(expected.RequiredCapabilities) || len(cert.Artifacts) != len(expected.Artifacts) {
		return errors.New("Windows Protection GA cohort size mismatch")
	}
	for i := range expected.JavaMajors {
		if cert.JavaMajors[i] != expected.JavaMajors[i] {
			return fmt.Errorf("Windows Protection GA Java major #%d mismatch", i+1)
		}
	}
	for i := range expected.RequiredCapabilities {
		if cert.RequiredCapabilities[i] != expected.RequiredCapabilities[i] {
			return fmt.Errorf("Windows Protection GA capability #%d mismatch", i+1)
		}
	}
	for i := range expected.Artifacts {
		a, b := cert.Artifacts[i], expected.Artifacts[i]
		if a.Name != b.Name || a.Size != b.Size || !strings.EqualFold(a.SHA256, b.SHA256) {
			return fmt.Errorf("Windows Protection GA artifact mismatch: %s", b.Name)
		}
	}
	for key := range expected.Invariants {
		if !cert.Invariants[key] {
			return fmt.Errorf("Windows Protection GA invariant %s is not satisfied", key)
		}
	}
	if !strings.EqualFold(cert.BoundarySHA256, expected.BoundarySHA256) || cert.CertificateID != "sha256:"+strings.ToLower(expected.BoundarySHA256) {
		return errors.New("Windows Protection GA boundary/certificateId mismatch")
	}
	return nil
}
