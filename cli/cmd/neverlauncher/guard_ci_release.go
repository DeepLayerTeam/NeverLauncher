package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	guardCITargetsReleaseFile       = "GUARD_CI_TARGETS.json"
	guardCIMatrixReleaseFile        = "GUARD_CI_MATRIX.json"
	guardCICertificationReleaseFile = "GUARD_CI_CERTIFICATION.json"
)

const guardCILimitation0139 = "ci-certifies-build-test-artifacts-not-vendor-signing-credentials"

var guardCISHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type releaseGuardCITarget struct {
	ID             string   `json:"id"`
	Runner         string   `json:"runner"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	Required       bool     `json:"required"`
	CISigningMode  string   `json:"ciSigningMode"`
	RequiredChecks []string `json:"requiredChecks"`
}

type releaseGuardCITargets struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	ProductVersion string                 `json:"productVersion"`
	Targets        []releaseGuardCITarget `json:"targets"`
}

type releaseGuardCIArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type releaseGuardCIResult struct {
	SchemaVersion  string                            `json:"schemaVersion"`
	ProductVersion string                            `json:"productVersion"`
	TargetID       string                            `json:"targetId"`
	Runner         string                            `json:"runner"`
	OS             string                            `json:"os"`
	Arch           string                            `json:"arch"`
	RuntimeArch    string                            `json:"runtimeArch"`
	Commit         string                            `json:"commit"`
	RunID          string                            `json:"runId"`
	Status         string                            `json:"status"`
	ExitCode       int                               `json:"exitCode"`
	Checks         map[string]bool                   `json:"checks"`
	Artifacts      map[string]releaseGuardCIArtifact `json:"artifacts"`
	Claims         map[string]any                    `json:"claims"`
	Limitations    []string                          `json:"limitations"`
	EvidenceSHA256 string                            `json:"evidenceSha256"`
}

type releaseGuardCIMatrix struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	ProductVersion string                 `json:"productVersion"`
	GeneratedAt    string                 `json:"generatedAt"`
	Repository     string                 `json:"repository"`
	Commit         string                 `json:"commit"`
	RunID          string                 `json:"runId"`
	Status         string                 `json:"status"`
	Targets        []releaseGuardCIResult `json:"targets"`
	Errors         []string               `json:"errors"`
}

type releaseGuardCertifiedArtifact struct {
	TargetID string `json:"targetId"`
	Role     string `json:"role"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type releaseGuardCICertification struct {
	SchemaVersion      string                          `json:"schemaVersion"`
	ProductVersion     string                          `json:"productVersion"`
	CertifiedAt        string                          `json:"certifiedAt"`
	Repository         string                          `json:"repository"`
	Commit             string                          `json:"commit"`
	RunID              string                          `json:"runId"`
	MatrixSHA256       string                          `json:"matrixSha256"`
	TargetsSHA256      string                          `json:"targetsSha256"`
	RequiredTargetIDs  []string                        `json:"requiredTargetIds"`
	PassedTargetIDs    []string                        `json:"passedTargetIds"`
	CertifiedArtifacts []releaseGuardCertifiedArtifact `json:"certifiedArtifacts"`
	Policy             string                          `json:"policy"`
	VendorSigningClaim string                          `json:"vendorSigningClaim"`
}

func guardCICertificationRequired(ver string) bool {
	parts := strings.SplitN(strings.TrimSpace(ver), ".", 3)
	if len(parts) != 3 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patchText := parts[2]
	if index := strings.IndexAny(patchText, "-+"); index >= 0 {
		patchText = patchText[:index]
	}
	patch, err3 := strconv.Atoi(patchText)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 13 {
		return minor > 13
	}
	return patch >= 9
}

func embedGuardCICertification(out, matrixPath, targetsPath, ver, expectedCommit string) error {
	if strings.TrimSpace(matrixPath) == "" || strings.TrimSpace(targetsPath) == "" {
		return errors.New("Guard CI matrix/targets path пуст")
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("read Guard CI matrix: %w", err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("read Guard CI targets: %w", err)
	}
	certification, err := validateGuardCIEvidence(matrixRaw, targetsRaw, ver, expectedCommit)
	if err != nil {
		return err
	}
	if err := verifyGuardCIArtifactsInDir(out, certification.CertifiedArtifacts); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, guardCIMatrixReleaseFile), matrixRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, guardCITargetsReleaseFile), targetsRaw, 0o644); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(out, guardCICertificationReleaseFile), certification)
}

func expectedGuardArtifactNames0139(osName, ver string) map[string]string {
	switch strings.ToLower(osName) {
	case "linux":
		return map[string]string{
			"package":   "neverlauncher-desktop-" + ver + "-linux-amd64.zip",
			"launcher":  "neverlauncher-desktop-linux-amd64",
			"guard":     "neverguard-linux-amd64",
			"manifest":  "LINUX_PACKAGE_MANIFEST.json",
			"allowlist": "GUARD_RELEASE_ALLOWLIST_LINUX.json",
		}
	case "windows":
		return map[string]string{
			"package":   "neverlauncher-desktop-" + ver + "-windows-amd64.zip",
			"launcher":  "neverlauncher-desktop-windows-amd64.exe",
			"guard":     "neverguard-windows-amd64.exe",
			"manifest":  "WINDOWS_PACKAGE_MANIFEST.json",
			"allowlist": "GUARD_RELEASE_ALLOWLIST_WINDOWS.json",
		}
	case "macos":
		return map[string]string{
			"package":   "neverlauncher-desktop-" + ver + "-macos-universal.zip",
			"launcher":  "neverlauncher-desktop-macos-universal",
			"guard":     "neverguard-macos-universal",
			"manifest":  "MACOS_PACKAGE_MANIFEST.json",
			"allowlist": "GUARD_RELEASE_ALLOWLIST_MACOS.json",
		}
	default:
		return nil
	}
}

func validateGuardCIEvidence(matrixRaw, targetsRaw []byte, ver, expectedCommit string) (releaseGuardCICertification, error) {
	var targets releaseGuardCITargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		return releaseGuardCICertification{}, fmt.Errorf("GUARD_CI_TARGETS invalid: %w", err)
	}
	var matrix releaseGuardCIMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return releaseGuardCICertification{}, fmt.Errorf("GUARD_CI_MATRIX invalid: %w", err)
	}
	if targets.SchemaVersion != "1.0" || matrix.SchemaVersion != "1.0" {
		return releaseGuardCICertification{}, errors.New("Guard CI evidence требует schemaVersion=1.0")
	}
	if strings.TrimSpace(ver) == "" || targets.ProductVersion != ver || matrix.ProductVersion != ver {
		return releaseGuardCICertification{}, fmt.Errorf("Guard CI productVersion mismatch: release=%s targets=%s matrix=%s", ver, targets.ProductVersion, matrix.ProductVersion)
	}
	if matrix.Status != "passed" || len(matrix.Errors) != 0 {
		return releaseGuardCICertification{}, errors.New("Guard CI matrix не имеет fail-closed status=passed")
	}
	if strings.TrimSpace(matrix.Repository) == "" || strings.TrimSpace(matrix.Commit) == "" || strings.TrimSpace(matrix.RunID) == "" {
		return releaseGuardCICertification{}, errors.New("Guard CI matrix не содержит repository/commit/runId")
	}
	if strings.TrimSpace(expectedCommit) != "" && matrix.Commit != strings.TrimSpace(expectedCommit) {
		return releaseGuardCICertification{}, fmt.Errorf("Guard CI matrix commit mismatch: expected=%s actual=%s", strings.TrimSpace(expectedCommit), matrix.Commit)
	}

	commonChecks := map[string]bool{
		"rustFormat": true, "guardUnitTests": true, "guardIntegrationTest": true, "clippy": true,
		"releaseBuild": true, "packageManifestVerified": true, "artifactHashesVerified": true,
		"authenticatedIpcV4": true, "runtimePolicyEnforced": true, "releasePackageBuilt": true,
		"guardRelease0139": true,
	}
	osCheck := map[string]string{"linux": "linuxProductionGate", "windows": "windowsProductionGate", "macos": "macosProductionGate"}
	expectedArch := map[string]string{"linux": "x86_64", "windows": "x86_64", "macos": "universal"}
	expectedSigning := map[string]string{"linux": "none-linux-integrity", "windows": "unsigned-development-ci", "macos": "adhoc-ci"}

	targetByID := map[string]releaseGuardCITarget{}
	requiredIDs := []string{}
	requiredOS := map[string]bool{}
	for _, target := range targets.Targets {
		id := strings.TrimSpace(target.ID)
		osName := strings.ToLower(strings.TrimSpace(target.OS))
		if id == "" || targetByID[id].ID != "" {
			return releaseGuardCICertification{}, fmt.Errorf("invalid or duplicate Guard CI target: %s", id)
		}
		if osCheck[osName] == "" || target.Arch != expectedArch[osName] || strings.TrimSpace(target.Runner) == "" || target.CISigningMode != expectedSigning[osName] {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target identity/policy invalid: %s", id)
		}
		checks := map[string]bool{}
		for _, check := range target.RequiredChecks {
			if strings.TrimSpace(check) == "" || checks[check] {
				return releaseGuardCICertification{}, fmt.Errorf("target %s содержит пустой/duplicate required check", id)
			}
			checks[check] = true
		}
		for check := range commonChecks {
			if !checks[check] {
				return releaseGuardCICertification{}, fmt.Errorf("target %s ослабляет Guard certification: missing %s", id, check)
			}
		}
		if !checks[osCheck[osName]] {
			return releaseGuardCICertification{}, fmt.Errorf("target %s ослабляет platform Guard gate: missing %s", id, osCheck[osName])
		}
		targetByID[id] = target
		if target.Required {
			requiredIDs = append(requiredIDs, id)
			requiredOS[osName] = true
		}
	}
	for _, osName := range []string{"linux", "windows", "macos"} {
		if !requiredOS[osName] {
			return releaseGuardCICertification{}, fmt.Errorf("Guard release certification требует required target для %s", osName)
		}
	}

	resultByID := map[string]releaseGuardCIResult{}
	for _, result := range matrix.Targets {
		if _, ok := targetByID[result.TargetID]; !ok {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI matrix содержит unexpected target: %s", result.TargetID)
		}
		if _, exists := resultByID[result.TargetID]; exists {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI matrix содержит duplicate target: %s", result.TargetID)
		}
		resultByID[result.TargetID] = result
	}
	if len(resultByID) != len(targetByID) {
		return releaseGuardCICertification{}, fmt.Errorf("Guard CI matrix target count mismatch: expected=%d actual=%d", len(targetByID), len(resultByID))
	}

	roles := []string{"package", "launcher", "guard", "manifest", "allowlist"}
	certifiedArtifacts := []releaseGuardCertifiedArtifact{}
	artifactNames := map[string]bool{}
	passedIDs := []string{}
	for id, target := range targetByID {
		result := resultByID[id]
		if result.SchemaVersion != "1.0" || result.ProductVersion != ver || result.Status != "passed" || result.ExitCode != 0 {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s не имеет валидный PASS/exitCode=0", id)
		}
		if result.Runner != target.Runner || result.OS != target.OS || result.Arch != target.Arch || strings.TrimSpace(result.RuntimeArch) == "" || result.Commit != matrix.Commit || result.RunID != matrix.RunID {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s identity/commit/runId mismatch", id)
		}
		for _, check := range target.RequiredChecks {
			if result.Checks == nil || result.Checks[check] != true {
				return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s required check %s != true", id, check)
			}
		}
		if !guardCISHA256RE.MatchString(strings.ToLower(result.EvidenceSHA256)) {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s не содержит valid evidenceSha256", id)
		}
		if fmt.Sprint(result.Claims["guardProtocolVersion"]) != "4" || fmt.Sprint(result.Claims["releaseCertification"]) != ver || fmt.Sprint(result.Claims["ciSigningMode"]) != target.CISigningMode || fmt.Sprint(result.Claims["vendorSigningProvenance"]) != "not-certified-by-ci" {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s содержит неверные release/security claims", id)
		}
		if result.Claims["packageManifestBound"] != true || result.Claims["artifactSetComplete"] != true {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s не подтверждает package manifest/artifact set", id)
		}
		limitationFound := false
		for _, limitation := range result.Limitations {
			if limitation == guardCILimitation0139 {
				limitationFound = true
				break
			}
		}
		if !limitationFound {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s overclaims vendor signing provenance", id)
		}
		expectedNames := expectedGuardArtifactNames0139(result.OS, ver)
		if len(result.Artifacts) != len(roles) {
			return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s artifact set incomplete", id)
		}
		for _, role := range roles {
			artifact, ok := result.Artifacts[role]
			if !ok || artifact.Name != expectedNames[role] || artifact.Size <= 0 || !guardCISHA256RE.MatchString(strings.ToLower(artifact.SHA256)) {
				return releaseGuardCICertification{}, fmt.Errorf("Guard CI target %s invalid certified artifact %s", id, role)
			}
			if filepath.Base(artifact.Name) != artifact.Name || artifactNames[artifact.Name] {
				return releaseGuardCICertification{}, fmt.Errorf("Guard CI artifact name unsafe/duplicate: %s", artifact.Name)
			}
			artifactNames[artifact.Name] = true
			certifiedArtifacts = append(certifiedArtifacts, releaseGuardCertifiedArtifact{TargetID: id, Role: role, Name: artifact.Name, Size: artifact.Size, SHA256: strings.ToLower(artifact.SHA256)})
		}
		passedIDs = append(passedIDs, id)
	}

	sort.Strings(requiredIDs)
	sort.Strings(passedIDs)
	sort.Slice(certifiedArtifacts, func(i, j int) bool {
		if certifiedArtifacts[i].Name == certifiedArtifacts[j].Name {
			return certifiedArtifacts[i].Role < certifiedArtifacts[j].Role
		}
		return certifiedArtifacts[i].Name < certifiedArtifacts[j].Name
	})
	matrixHash := sha256.Sum256(matrixRaw)
	targetsHash := sha256.Sum256(targetsRaw)
	return releaseGuardCICertification{
		SchemaVersion: "1.0", ProductVersion: ver, CertifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Repository: matrix.Repository, Commit: matrix.Commit, RunID: matrix.RunID,
		MatrixSHA256: hex.EncodeToString(matrixHash[:]), TargetsSHA256: hex.EncodeToString(targetsHash[:]),
		RequiredTargetIDs: requiredIDs, PassedTargetIDs: passedIDs, CertifiedArtifacts: certifiedArtifacts,
		Policy:             "all-required-cross-platform-guard-targets-pass-exact-commit-and-release-artifact-hashes",
		VendorSigningClaim: "not-certified-by-ci; production platform signing remains enforced by platform release builders",
	}, nil
}

func verifyGuardCIArtifactsInDir(dir string, artifacts []releaseGuardCertifiedArtifact) error {
	for _, artifact := range artifacts {
		if filepath.Base(artifact.Name) != artifact.Name {
			return fmt.Errorf("unsafe certified Guard artifact path: %s", artifact.Name)
		}
		actual, size, err := hashFile(filepath.Join(dir, artifact.Name))
		if err != nil {
			return fmt.Errorf("certified Guard artifact %s missing: %w", artifact.Name, err)
		}
		if size != artifact.Size || !strings.EqualFold(actual, artifact.SHA256) {
			return fmt.Errorf("certified Guard artifact mismatch: %s", artifact.Name)
		}
	}
	return nil
}

func verifyGuardCICertificationInBundle(dir, ver string) error {
	matrixRaw, err := os.ReadFile(filepath.Join(dir, guardCIMatrixReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", guardCIMatrixReleaseFile, err)
	}
	targetsRaw, err := os.ReadFile(filepath.Join(dir, guardCITargetsReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", guardCITargetsReleaseFile, err)
	}
	certRaw, err := os.ReadFile(filepath.Join(dir, guardCICertificationReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", guardCICertificationReleaseFile, err)
	}
	var stored releaseGuardCICertification
	if err := json.Unmarshal(certRaw, &stored); err != nil {
		return fmt.Errorf("%s invalid: %w", guardCICertificationReleaseFile, err)
	}
	expected, err := validateGuardCIEvidence(matrixRaw, targetsRaw, ver, stored.Commit)
	if err != nil {
		return err
	}
	if stored.SchemaVersion != expected.SchemaVersion || stored.ProductVersion != expected.ProductVersion || stored.Repository != expected.Repository || stored.Commit != expected.Commit || stored.RunID != expected.RunID || stored.MatrixSHA256 != expected.MatrixSHA256 || stored.TargetsSHA256 != expected.TargetsSHA256 || stored.Policy != expected.Policy || stored.VendorSigningClaim != expected.VendorSigningClaim {
		return errors.New("GUARD_CI_CERTIFICATION не соответствует embedded matrix/targets")
	}
	if !reflect.DeepEqual(stored.RequiredTargetIDs, expected.RequiredTargetIDs) || !reflect.DeepEqual(stored.PassedTargetIDs, expected.PassedTargetIDs) || !reflect.DeepEqual(stored.CertifiedArtifacts, expected.CertifiedArtifacts) {
		return errors.New("GUARD_CI_CERTIFICATION target/artifact sets mismatch")
	}
	return verifyGuardCIArtifactsInDir(dir, stored.CertifiedArtifacts)
}

func guardCIArtifactNamesFromBundle(dir string) []string {
	raw, err := os.ReadFile(filepath.Join(dir, guardCICertificationReleaseFile))
	if err != nil {
		return nil
	}
	var certification releaseGuardCICertification
	if json.Unmarshal(raw, &certification) != nil {
		return nil
	}
	names := make([]string, 0, len(certification.CertifiedArtifacts))
	for _, artifact := range certification.CertifiedArtifacts {
		names = append(names, artifact.Name)
	}
	sort.Strings(names)
	return names
}
