package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	productionDeliveryReleaseFile0160    = "PRODUCTION_DELIVERY_RELEASE.json"
	productionDeliveryReleaseSchema0160  = "1.0"
	productionDeliveryReleaseStatus0160  = "production-delivery-release"
	productionDeliveryReleaseChannel0160 = "stable"
)

type productionDeliveryReleaseAnchor0160 struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type productionDeliveryRelease0160 struct {
	SchemaVersion         string                                `json:"schemaVersion"`
	Product               string                                `json:"product"`
	Version               string                                `json:"version"`
	Status                string                                `json:"status"`
	Channel               string                                `json:"channel"`
	SourceCommit          string                                `json:"sourceCommit"`
	CreatedAt             string                                `json:"createdAt"`
	CandidateSHA256       string                                `json:"candidateSha256"`
	CandidateCohortSHA256 string                                `json:"candidateCohortSha256"`
	PublicBaseURL         string                                `json:"publicBaseUrl"`
	BoundarySHA256        string                                `json:"boundarySha256"`
	PublishedTargets      []DeliveryTarget                      `json:"publishedTargets"`
	Anchors               []productionDeliveryReleaseAnchor0160 `json:"anchors"`
	RequiredGates         []string                              `json:"requiredGates"`
	PostPublishE2E        bool                                  `json:"postPublishE2ERequired"`
}

func productionDeliveryReleaseRequired0160(ver string) bool {
	major, minor, _, ok := parseCoreVersion(ver)
	if !ok {
		return false
	}
	return major > 0 || (major == 0 && minor >= 16)
}

func stableProductionVersion0160(ver string) error {
	ver = strings.TrimSpace(ver)
	if !productionDeliveryReleaseRequired0160(ver) {
		return fmt.Errorf("production delivery release requires version >=0.16.0, got %q", ver)
	}
	if strings.ContainsAny(ver, "-+") {
		return fmt.Errorf("production delivery release must use immutable GA SemVer without prerelease/build suffix: %q", ver)
	}
	return nil
}

func productionDeliveryReleaseRequiredGates0160() []string {
	return []string{
		"production-release-candidate-exact-source-cohort",
		"windows-x64-arm64-authenticode-rfc3161",
		"linux-x64-arm64-production-packages",
		"macos-x64-arm64-developer-id-notarization",
		"managed-jre-temurin21-six-target-distribution",
		"release-verification-v2-trust-lifecycle-anti-rollback",
		"public-production-delivery-matrix-six-target-e2e",
		"unified-transactional-updater-core",
		"desktop-guard-runtime-transactional-update",
		"migration-stabilization-0.15.10",
		"stable-versioned-public-origin",
		"production-delivery-release-boundary",
	}
}

func productionDeliveryReleaseAnchorNames0160() []string {
	return []string{
		productionReleaseCandidateFile01511,
		deliveryManifestFile0151,
		publicProductionDeliveryMatrixFile0159,
		windowsSigningEvidenceFile0152,
		linuxProductionEvidenceFile0153,
		macOSNotarizationEvidenceFile0154,
		managedJREManifestFile0155,
		managedJREEvidenceFile0155,
		releaseTrustPolicyFile0158,
		compatibilityCertificationReleaseFile,
		deviceTrustCertificationReleaseFile,
		guardCICertificationReleaseFile,
		serverBridge2CertificationReleaseFile,
		"SBOM.spdx.json",
		"PROVENANCE.json",
	}
}

func productionDeliveryReleaseAnchors0160(dir string) ([]productionDeliveryReleaseAnchor0160, error) {
	names := append([]string(nil), productionDeliveryReleaseAnchorNames0160()...)
	sort.Strings(names)
	anchors := make([]productionDeliveryReleaseAnchor0160, 0, len(names))
	for _, name := range names {
		clean, err := safeReleaseRelativePath0158(name)
		if err != nil || clean != name {
			return nil, fmt.Errorf("production delivery release anchor path invalid: %q", name)
		}
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("production delivery release anchor %s: %w", name, err)
		}
		anchors = append(anchors, productionDeliveryReleaseAnchor0160{Name: name, Size: size, SHA256: strings.ToLower(sum)})
	}
	return anchors, nil
}

func productionDeliveryReleaseBoundaryDigest0160(anchors []productionDeliveryReleaseAnchor0160, targets []DeliveryTarget, ver, commit, baseURL string) string {
	h := sha256.New()
	fmt.Fprintf(h, "NeverLauncher\n%s\n%s\n%s\n%s\n", ver, strings.ToLower(commit), productionDeliveryReleaseChannel0160, baseURL)
	for _, target := range targets {
		fmt.Fprintf(h, "target %s/%s\n", target.Platform, target.Architecture)
	}
	for _, anchor := range anchors {
		fmt.Fprintf(h, "%s  %d  %s\n", strings.ToLower(anchor.SHA256), anchor.Size, anchor.Name)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func versionedPublicBaseURL0160(raw, ver string) (string, error) {
	base, err := normalizePublicBaseURL0159(raw, false)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	found := false
	for _, segment := range strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "", err
		}
		if decoded == ver || decoded == "v"+ver {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("production public base URL must contain immutable version segment %q or %q: %s", ver, "v"+ver, base)
	}
	return base, nil
}

func readProductionCandidateForRelease0160(dir, ver string) (productionReleaseCandidate01511, string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, productionReleaseCandidateFile01511))
	if err != nil {
		return productionReleaseCandidate01511{}, "", err
	}
	var candidate productionReleaseCandidate01511
	if err := json.Unmarshal(raw, &candidate); err != nil {
		return candidate, "", err
	}
	commit, err := verifyProductionReleaseCandidateDocument01511(dir, ver)
	return candidate, commit, err
}

func expectedProductionTargets0160() []DeliveryTarget {
	return []DeliveryTarget{
		{Platform: "linux", Architecture: "arm64"},
		{Platform: "linux", Architecture: "x64"},
		{Platform: "macos", Architecture: "arm64"},
		{Platform: "macos", Architecture: "x64"},
		{Platform: "windows", Architecture: "arm64"},
		{Platform: "windows", Architecture: "x64"},
	}
}

func validateProductionTargets0160(targets []DeliveryTarget) error {
	if len(targets) != 6 {
		return fmt.Errorf("production delivery release requires exactly six published targets, got %d", len(targets))
	}
	actual := append([]DeliveryTarget(nil), targets...)
	sort.Slice(actual, func(i, j int) bool {
		if actual[i].Platform == actual[j].Platform {
			return actual[i].Architecture < actual[j].Architecture
		}
		return actual[i].Platform < actual[j].Platform
	})
	expected := expectedProductionTargets0160()
	for i := range expected {
		if actual[i] != expected[i] {
			return fmt.Errorf("production delivery target mismatch at #%d: expected=%s/%s actual=%s/%s", i+1, expected[i].Platform, expected[i].Architecture, actual[i].Platform, actual[i].Architecture)
		}
	}
	return nil
}

func buildProductionDeliveryReleaseDocument0160(dir, ver string) (productionDeliveryRelease0160, error) {
	if err := stableProductionVersion0160(ver); err != nil {
		return productionDeliveryRelease0160{}, err
	}
	candidate, commit, err := readProductionCandidateForRelease0160(dir, ver)
	if err != nil {
		return productionDeliveryRelease0160{}, fmt.Errorf("production candidate: %w", err)
	}
	matrix, err := readPublicProductionDeliveryMatrix0159(filepath.Join(dir, publicProductionDeliveryMatrixFile0159))
	if err != nil {
		return productionDeliveryRelease0160{}, err
	}
	if matrix.Version != ver || matrix.Channel != productionDeliveryReleaseChannel0160 {
		return productionDeliveryRelease0160{}, errors.New("public delivery matrix is not the stable target version")
	}
	baseURL, err := versionedPublicBaseURL0160(matrix.BaseURL, ver)
	if err != nil {
		return productionDeliveryRelease0160{}, err
	}
	targets := make([]DeliveryTarget, 0, len(matrix.Targets))
	for _, target := range matrix.Targets {
		targets = append(targets, DeliveryTarget{Platform: target.Platform, Architecture: target.Architecture})
	}
	if err := validateProductionTargets0160(targets); err != nil {
		return productionDeliveryRelease0160{}, err
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Platform == targets[j].Platform {
			return targets[i].Architecture < targets[j].Architecture
		}
		return targets[i].Platform < targets[j].Platform
	})
	anchors, err := productionDeliveryReleaseAnchors0160(dir)
	if err != nil {
		return productionDeliveryRelease0160{}, err
	}
	candidateSHA, _, err := hashFile(filepath.Join(dir, productionReleaseCandidateFile01511))
	if err != nil {
		return productionDeliveryRelease0160{}, err
	}
	return productionDeliveryRelease0160{
		SchemaVersion:         productionDeliveryReleaseSchema0160,
		Product:               "NeverLauncher",
		Version:               ver,
		Status:                productionDeliveryReleaseStatus0160,
		Channel:               productionDeliveryReleaseChannel0160,
		SourceCommit:          commit,
		CreatedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		CandidateSHA256:       strings.ToLower(candidateSHA),
		CandidateCohortSHA256: strings.ToLower(candidate.CohortSHA256),
		PublicBaseURL:         baseURL,
		BoundarySHA256:        productionDeliveryReleaseBoundaryDigest0160(anchors, targets, ver, commit, baseURL),
		PublishedTargets:      targets,
		Anchors:               anchors,
		RequiredGates:         productionDeliveryReleaseRequiredGates0160(),
		PostPublishE2E:        true,
	}, nil
}

func writeProductionDeliveryRelease0160(dir, ver string) error {
	doc, err := buildProductionDeliveryReleaseDocument0160(dir, ver)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, productionDeliveryReleaseFile0160), doc)
}

func verifyProductionDeliveryReleaseDocument0160(dir, ver string) (string, error) {
	if err := stableProductionVersion0160(ver); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(dir, productionDeliveryReleaseFile0160))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", productionDeliveryReleaseFile0160, err)
	}
	var doc productionDeliveryRelease0160
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("invalid %s: %w", productionDeliveryReleaseFile0160, err)
	}
	commit, err := normalizeSourceCommit01511(doc.SourceCommit)
	if err != nil {
		return "", err
	}
	if doc.SchemaVersion != productionDeliveryReleaseSchema0160 || doc.Product != "NeverLauncher" || doc.Version != ver || doc.Status != productionDeliveryReleaseStatus0160 || doc.Channel != productionDeliveryReleaseChannel0160 || !doc.PostPublishE2E {
		return "", errors.New("production delivery release metadata mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, doc.CreatedAt); err != nil {
		return "", fmt.Errorf("production delivery release createdAt invalid: %w", err)
	}
	baseURL, err := versionedPublicBaseURL0160(doc.PublicBaseURL, ver)
	if err != nil || baseURL != doc.PublicBaseURL {
		return "", errors.New("production delivery release publicBaseUrl is invalid")
	}
	candidate, candidateCommit, err := readProductionCandidateForRelease0160(dir, ver)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(commit, candidateCommit) {
		return "", errors.New("production delivery release source commit does not match candidate")
	}
	candidateSHA, _, err := hashFile(filepath.Join(dir, productionReleaseCandidateFile01511))
	if err != nil || !strings.EqualFold(candidateSHA, doc.CandidateSHA256) || !strings.EqualFold(candidate.CohortSHA256, doc.CandidateCohortSHA256) {
		return "", errors.New("production delivery release candidate binding mismatch")
	}
	expectedGates := productionDeliveryReleaseRequiredGates0160()
	if len(doc.RequiredGates) != len(expectedGates) {
		return "", errors.New("production delivery release required gate set mismatch")
	}
	for i := range expectedGates {
		if doc.RequiredGates[i] != expectedGates[i] {
			return "", fmt.Errorf("production delivery release gate #%d mismatch", i+1)
		}
	}
	if err := validateProductionTargets0160(doc.PublishedTargets); err != nil {
		return "", err
	}
	anchors, err := productionDeliveryReleaseAnchors0160(dir)
	if err != nil {
		return "", err
	}
	if len(anchors) != len(doc.Anchors) {
		return "", errors.New("production delivery release anchor count mismatch")
	}
	for i := range anchors {
		if anchors[i] != doc.Anchors[i] {
			return "", fmt.Errorf("production delivery release anchor mismatch at %s", anchors[i].Name)
		}
	}
	targets := append([]DeliveryTarget(nil), doc.PublishedTargets...)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Platform == targets[j].Platform {
			return targets[i].Architecture < targets[j].Architecture
		}
		return targets[i].Platform < targets[j].Platform
	})
	expectedBoundary := productionDeliveryReleaseBoundaryDigest0160(anchors, targets, ver, commit, doc.PublicBaseURL)
	if !strings.EqualFold(expectedBoundary, doc.BoundarySHA256) {
		return "", errors.New("production delivery release boundarySha256 mismatch")
	}
	matrix, err := readPublicProductionDeliveryMatrix0159(filepath.Join(dir, publicProductionDeliveryMatrixFile0159))
	if err != nil {
		return "", err
	}
	if matrix.Version != ver || matrix.Channel != doc.Channel || matrix.BaseURL != doc.PublicBaseURL {
		return "", errors.New("production delivery release/public matrix binding mismatch")
	}
	return commit, nil
}

func verifyProductionDeliveryRelease0160(dir, ver string, strict bool) error {
	if !productionDeliveryReleaseRequired0160(ver) {
		return nil
	}
	if err := verifyProductionReleaseCandidate01511(dir, ver, true); err != nil {
		return fmt.Errorf("production candidate prerequisite: %w", err)
	}
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		return fmt.Errorf("delivery manifest: %w", err)
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, strict); err != nil {
		return fmt.Errorf("Windows signing: %w", err)
	}
	if err := verifyLinuxProductionEvidence0153(dir, ver, true); err != nil {
		return fmt.Errorf("Linux delivery: %w", err)
	}
	if err := verifyMacOSNotarizationEvidence0154(dir, ver, strict); err != nil {
		return fmt.Errorf("macOS delivery: %w", err)
	}
	if err := verifyManagedJREDistribution0155(dir, ver, true); err != nil {
		return fmt.Errorf("Managed JRE: %w", err)
	}
	if err := verifyPublicProductionDeliveryMatrix0159(dir, ver); err != nil {
		return fmt.Errorf("public production delivery matrix: %w", err)
	}
	if _, err := loadReleaseTrustPolicy0158(filepath.Join(dir, releaseTrustPolicyFile0158)); err != nil {
		return fmt.Errorf("release trust policy: %w", err)
	}
	_, err := verifyProductionDeliveryReleaseDocument0160(dir, ver)
	return err
}
