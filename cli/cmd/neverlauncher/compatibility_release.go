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
	compatibilityTargetsReleaseFile       = "COMPATIBILITY_TARGETS.json"
	compatibilityMatrixReleaseFile        = "COMPATIBILITY_MATRIX.json"
	compatibilityCertificationReleaseFile = "COMPATIBILITY_CERTIFICATION.json"
)

var compatibilitySHA256RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type releaseCompatibilityTarget struct {
	ID            string `json:"id"`
	Minecraft     string `json:"minecraft"`
	Loader        string `json:"loader"`
	LoaderVersion string `json:"loaderVersion"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Required      bool   `json:"required"`
}

type releaseCompatibilityTargets struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	ProductVersion string                       `json:"productVersion"`
	Targets        []releaseCompatibilityTarget `json:"targets"`
}

type releaseCompatibilityResult struct {
	SchemaVersion         string          `json:"schemaVersion"`
	ProductVersion        string          `json:"productVersion"`
	TargetID              string          `json:"targetId"`
	Status                string          `json:"status"`
	MinecraftVersion      string          `json:"minecraftVersion"`
	Loader                string          `json:"loader"`
	LoaderSelector        string          `json:"loaderSelector"`
	ResolvedLoaderVersion string          `json:"resolvedLoaderVersion"`
	OS                    string          `json:"os"`
	Arch                  string          `json:"arch"`
	Commit                string          `json:"commit"`
	RunID                 string          `json:"runId"`
	ExitCode              int             `json:"exitCode"`
	Checks                map[string]bool `json:"checks"`
	EvidenceSHA256        string          `json:"evidenceSha256"`
}

type releaseCompatibilityMatrix struct {
	SchemaVersion  string                       `json:"schemaVersion"`
	ProductVersion string                       `json:"productVersion"`
	GeneratedAt    string                       `json:"generatedAt"`
	Repository     string                       `json:"repository"`
	Commit         string                       `json:"commit"`
	RunID          string                       `json:"runId"`
	Status         string                       `json:"status"`
	Targets        []releaseCompatibilityResult `json:"targets"`
	Errors         []string                     `json:"errors"`
}

type releaseCompatibilityCertification struct {
	SchemaVersion     string   `json:"schemaVersion"`
	ProductVersion    string   `json:"productVersion"`
	CertifiedAt       string   `json:"certifiedAt"`
	Repository        string   `json:"repository"`
	Commit            string   `json:"commit"`
	RunID             string   `json:"runId"`
	MatrixSHA256      string   `json:"matrixSha256"`
	TargetsSHA256     string   `json:"targetsSha256"`
	RequiredTargetIDs []string `json:"requiredTargetIds"`
	PassedTargetIDs   []string `json:"passedTargetIds"`
	LoaderFamilies    []string `json:"loaderFamilies"`
	Policy            string   `json:"policy"`
}

func compatibilityCertificationRequired(ver string) bool {
	parts := strings.SplitN(strings.TrimSpace(ver), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 0 || minor >= 11
}

func embedCompatibilityCertification(out, matrixPath, targetsPath, ver, expectedCommit string) error {
	if strings.TrimSpace(matrixPath) == "" {
		return errors.New("compatibility matrix path пуст")
	}
	if strings.TrimSpace(targetsPath) == "" {
		return errors.New("compatibility targets path пуст")
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("read compatibility matrix: %w", err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("read compatibility targets: %w", err)
	}
	certification, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, ver, expectedCommit)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, compatibilityMatrixReleaseFile), matrixRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, compatibilityTargetsReleaseFile), targetsRaw, 0o644); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(out, compatibilityCertificationReleaseFile), certification)
}

func validateCompatibilityEvidence(matrixRaw, targetsRaw []byte, ver, expectedCommit string) (releaseCompatibilityCertification, error) {
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		return releaseCompatibilityCertification{}, fmt.Errorf("COMPATIBILITY_TARGETS invalid: %w", err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return releaseCompatibilityCertification{}, fmt.Errorf("COMPATIBILITY_MATRIX invalid: %w", err)
	}
	if targets.SchemaVersion != "1.0" || matrix.SchemaVersion != "1.0" {
		return releaseCompatibilityCertification{}, errors.New("compatibility evidence требует schemaVersion=1.0")
	}
	if strings.TrimSpace(ver) == "" || targets.ProductVersion != ver || matrix.ProductVersion != ver {
		return releaseCompatibilityCertification{}, fmt.Errorf("compatibility productVersion mismatch: release=%s targets=%s matrix=%s", ver, targets.ProductVersion, matrix.ProductVersion)
	}
	if matrix.Status != "passed" || len(matrix.Errors) != 0 {
		return releaseCompatibilityCertification{}, errors.New("compatibility matrix не имеет fail-closed status=passed")
	}
	if strings.TrimSpace(matrix.Repository) == "" || strings.TrimSpace(matrix.Commit) == "" || strings.TrimSpace(matrix.RunID) == "" {
		return releaseCompatibilityCertification{}, errors.New("compatibility matrix не содержит repository/commit/runId")
	}
	if strings.TrimSpace(expectedCommit) != "" && matrix.Commit != strings.TrimSpace(expectedCommit) {
		return releaseCompatibilityCertification{}, fmt.Errorf("compatibility matrix commit mismatch: expected=%s actual=%s", strings.TrimSpace(expectedCommit), matrix.Commit)
	}

	allowedLoaders := map[string]bool{"vanilla": true, "fabric": true, "quilt": true, "forge": true, "neoforge": true}
	targetByID := map[string]releaseCompatibilityTarget{}
	requiredIDs := []string{}
	for _, target := range targets.Targets {
		id := strings.TrimSpace(target.ID)
		if id == "" {
			return releaseCompatibilityCertification{}, errors.New("compatibility target без id")
		}
		if _, exists := targetByID[id]; exists {
			return releaseCompatibilityCertification{}, fmt.Errorf("duplicate compatibility target: %s", id)
		}
		if !allowedLoaders[target.Loader] {
			return releaseCompatibilityCertification{}, fmt.Errorf("unsupported loader in compatibility target %s: %s", id, target.Loader)
		}
		if strings.TrimSpace(target.Minecraft) == "" || strings.TrimSpace(target.OS) == "" || strings.TrimSpace(target.Arch) == "" {
			return releaseCompatibilityCertification{}, fmt.Errorf("incomplete compatibility target: %s", id)
		}
		targetByID[id] = target
		if target.Required {
			requiredIDs = append(requiredIDs, id)
		}
	}
	if len(requiredIDs) == 0 {
		return releaseCompatibilityCertification{}, errors.New("compatibility targets не содержат required targets")
	}

	resultByID := map[string]releaseCompatibilityResult{}
	for _, result := range matrix.Targets {
		id := strings.TrimSpace(result.TargetID)
		if _, ok := targetByID[id]; !ok {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix содержит unexpected target: %s", id)
		}
		if _, exists := resultByID[id]; exists {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix содержит duplicate target: %s", id)
		}
		resultByID[id] = result
	}
	if len(resultByID) != len(targetByID) {
		return releaseCompatibilityCertification{}, fmt.Errorf("matrix target count mismatch: expected=%d actual=%d", len(targetByID), len(resultByID))
	}

	mandatoryChecks := []string{"actualClient", "packageVerified", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy"}
	passedIDs := []string{}
	loaderSet := map[string]bool{}
	mutable := map[string]bool{"latest": true, "latest-stable": true, "recommended": true, "stable": true}
	for id, target := range targetByID {
		result, ok := resultByID[id]
		if !ok {
			return releaseCompatibilityCertification{}, fmt.Errorf("matrix missing target: %s", id)
		}
		if result.SchemaVersion != "1.0" || result.ProductVersion != ver || result.Status != "passed" || result.ExitCode != 0 {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s не имеет валидный PASS/exitCode=0", id)
		}
		if result.MinecraftVersion != target.Minecraft || result.Loader != target.Loader || result.LoaderSelector != target.LoaderVersion || result.OS != target.OS || result.Arch != target.Arch {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s identity mismatch между targets и matrix", id)
		}
		if result.Commit != matrix.Commit || result.RunID != matrix.RunID {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s commit/runId не совпадает с aggregate matrix", id)
		}
		for _, check := range mandatoryChecks {
			if result.Checks == nil || result.Checks[check] != true {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s required check %s != true", id, check)
			}
		}
		if !compatibilitySHA256RE.MatchString(result.EvidenceSHA256) {
			return releaseCompatibilityCertification{}, fmt.Errorf("target %s не содержит валидный evidenceSha256", id)
		}
		if target.Loader == "vanilla" {
			if strings.TrimSpace(result.ResolvedLoaderVersion) != "" {
				return releaseCompatibilityCertification{}, fmt.Errorf("Vanilla target %s не должен иметь resolvedLoaderVersion", id)
			}
		} else {
			resolved := strings.ToLower(strings.TrimSpace(result.ResolvedLoaderVersion))
			if resolved == "" || mutable[resolved] {
				return releaseCompatibilityCertification{}, fmt.Errorf("target %s не разрешил loader в immutable version", id)
			}
		}
		passedIDs = append(passedIDs, id)
		loaderSet[target.Loader] = true
	}

	sort.Strings(requiredIDs)
	sort.Strings(passedIDs)
	loaderFamilies := make([]string, 0, len(loaderSet))
	for loader := range loaderSet {
		loaderFamilies = append(loaderFamilies, loader)
	}
	sort.Strings(loaderFamilies)
	matrixHash := sha256.Sum256(matrixRaw)
	targetsHash := sha256.Sum256(targetsRaw)
	return releaseCompatibilityCertification{
		SchemaVersion:     "1.0",
		ProductVersion:    ver,
		CertifiedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Repository:        matrix.Repository,
		Commit:            matrix.Commit,
		RunID:             matrix.RunID,
		MatrixSHA256:      hex.EncodeToString(matrixHash[:]),
		TargetsSHA256:     hex.EncodeToString(targetsHash[:]),
		RequiredTargetIDs: requiredIDs,
		PassedTargetIDs:   passedIDs,
		LoaderFamilies:    loaderFamilies,
		Policy:            "all-required-targets-must-pass-actual-client-e2e",
	}, nil
}

func verifyCompatibilityCertificationInBundle(dir, ver string) error {
	matrixPath := filepath.Join(dir, compatibilityMatrixReleaseFile)
	targetsPath := filepath.Join(dir, compatibilityTargetsReleaseFile)
	certPath := filepath.Join(dir, compatibilityCertificationReleaseFile)
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityMatrixReleaseFile, err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityTargetsReleaseFile, err)
	}
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("%s missing: %w", compatibilityCertificationReleaseFile, err)
	}
	var stored releaseCompatibilityCertification
	if err := json.Unmarshal(certRaw, &stored); err != nil {
		return fmt.Errorf("%s invalid: %w", compatibilityCertificationReleaseFile, err)
	}
	expected, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, ver, stored.Commit)
	if err != nil {
		return err
	}
	if stored.SchemaVersion != expected.SchemaVersion || stored.ProductVersion != expected.ProductVersion || stored.Repository != expected.Repository || stored.Commit != expected.Commit || stored.RunID != expected.RunID || stored.MatrixSHA256 != expected.MatrixSHA256 || stored.TargetsSHA256 != expected.TargetsSHA256 || stored.Policy != expected.Policy {
		return errors.New("COMPATIBILITY_CERTIFICATION не соответствует embedded matrix/targets")
	}
	if strings.Join(stored.RequiredTargetIDs, "\x00") != strings.Join(expected.RequiredTargetIDs, "\x00") || strings.Join(stored.PassedTargetIDs, "\x00") != strings.Join(expected.PassedTargetIDs, "\x00") || strings.Join(stored.LoaderFamilies, "\x00") != strings.Join(expected.LoaderFamilies, "\x00") {
		return errors.New("COMPATIBILITY_CERTIFICATION target/loader sets mismatch")
	}
	return nil
}
