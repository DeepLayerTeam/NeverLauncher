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
	deviceTrustTargetsReleaseFile       = "DEVICE_TRUST_TARGETS.json"
	deviceTrustMatrixReleaseFile        = "DEVICE_TRUST_MATRIX.json"
	deviceTrustCertificationReleaseFile = "DEVICE_TRUST_CERTIFICATION.json"
)

var deviceTrustSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type releaseDeviceTrustTarget struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Runner         string   `json:"runner"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	Required       bool     `json:"required"`
	RequiredChecks []string `json:"requiredChecks"`
}

type releaseDeviceTrustTargets struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	ProductVersion string                     `json:"productVersion"`
	Targets        []releaseDeviceTrustTarget `json:"targets"`
}

type releaseDeviceTrustResult struct {
	SchemaVersion  string          `json:"schemaVersion"`
	ProductVersion string          `json:"productVersion"`
	TargetID       string          `json:"targetId"`
	Kind           string          `json:"kind"`
	OS             string          `json:"os"`
	Arch           string          `json:"arch"`
	RuntimeArch    string          `json:"runtimeArch"`
	Commit         string          `json:"commit"`
	RunID          string          `json:"runId"`
	Status         string          `json:"status"`
	ExitCode       int             `json:"exitCode"`
	Checks         map[string]bool `json:"checks"`
	EvidenceSHA256 string          `json:"evidenceSha256"`
	Claims         map[string]any  `json:"claims"`
	Limitations    []string        `json:"limitations"`
}

type releaseDeviceTrustMatrix struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	ProductVersion string                     `json:"productVersion"`
	GeneratedAt    string                     `json:"generatedAt"`
	Repository     string                     `json:"repository"`
	Commit         string                     `json:"commit"`
	RunID          string                     `json:"runId"`
	Status         string                     `json:"status"`
	Targets        []releaseDeviceTrustResult `json:"targets"`
	Errors         []string                   `json:"errors"`
}

type releaseDeviceTrustCertification struct {
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
	Policy            string   `json:"policy"`
}

func deviceTrustCertificationRequired(ver string) bool {
	parts := strings.SplitN(strings.TrimSpace(ver), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 0 || minor >= 13
}

func embedDeviceTrustCertification(out, matrixPath, targetsPath, ver, expectedCommit string) error {
	if strings.TrimSpace(matrixPath) == "" {
		return errors.New("device trust matrix path пуст")
	}
	if strings.TrimSpace(targetsPath) == "" {
		return errors.New("device trust targets path пуст")
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("read Device Trust matrix: %w", err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("read Device Trust targets: %w", err)
	}
	certification, err := validateDeviceTrustEvidence(matrixRaw, targetsRaw, ver, expectedCommit)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, deviceTrustMatrixReleaseFile), matrixRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, deviceTrustTargetsReleaseFile), targetsRaw, 0o644); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(out, deviceTrustCertificationReleaseFile), certification)
}

func validateDeviceTrustEvidence(matrixRaw, targetsRaw []byte, ver, expectedCommit string) (releaseDeviceTrustCertification, error) {
	var targets releaseDeviceTrustTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		return releaseDeviceTrustCertification{}, fmt.Errorf("DEVICE_TRUST_TARGETS invalid: %w", err)
	}
	var matrix releaseDeviceTrustMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return releaseDeviceTrustCertification{}, fmt.Errorf("DEVICE_TRUST_MATRIX invalid: %w", err)
	}
	if targets.SchemaVersion != "1.0" || matrix.SchemaVersion != "1.0" {
		return releaseDeviceTrustCertification{}, errors.New("Device Trust evidence требует schemaVersion=1.0")
	}
	if strings.TrimSpace(ver) == "" || targets.ProductVersion != ver || matrix.ProductVersion != ver {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust productVersion mismatch: release=%s targets=%s matrix=%s", ver, targets.ProductVersion, matrix.ProductVersion)
	}
	if matrix.Status != "passed" || len(matrix.Errors) != 0 {
		return releaseDeviceTrustCertification{}, errors.New("Device Trust matrix не имеет fail-closed status=passed")
	}
	if strings.TrimSpace(matrix.Repository) == "" || strings.TrimSpace(matrix.Commit) == "" || strings.TrimSpace(matrix.RunID) == "" {
		return releaseDeviceTrustCertification{}, errors.New("Device Trust matrix не содержит repository/commit/runId")
	}
	if strings.TrimSpace(expectedCommit) != "" && matrix.Commit != strings.TrimSpace(expectedCommit) {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust matrix commit mismatch: expected=%s actual=%s", strings.TrimSpace(expectedCommit), matrix.Commit)
	}

	mandatoryProtocol := map[string]bool{
		"postgresRepository": true, "migrationStabilization01210": true, "registrationReplayDenied": true,
		"sessionBindingEpoch": true, "boundRefreshProof": true, "rotationDualProof": true,
		"oldKeyTombstone": true, "serverBridgeBindingDeny": true, "revocationCascade": true,
		"riskStepUp": true, "p256AttestationProtocol": true, "attestationReplayDenied": true,
		"recoveryRequiresPhishingResistantStepUp": true, "recoveryPhishingResistantEndToEnd": true,
		"deviceTrustRelease0130": true,
	}
	mandatoryNative := map[string]bool{
		"tauriCompile": true, "deviceKeyUnitTests": true, "generationScopedHardwareLabels": true,
		"replacementPayloadValidation": true, "refreshPayloadBinding": true, "attestationPayloadValidation": true,
		"deviceTrustRelease0130": true,
	}

	targetByID := map[string]releaseDeviceTrustTarget{}
	requiredIDs := []string{}
	requiredNativeOS := map[string]bool{}
	requiredProtocol := 0
	for _, target := range targets.Targets {
		id := strings.TrimSpace(target.ID)
		if id == "" {
			return releaseDeviceTrustCertification{}, errors.New("Device Trust target без id")
		}
		if _, exists := targetByID[id]; exists {
			return releaseDeviceTrustCertification{}, fmt.Errorf("duplicate Device Trust target: %s", id)
		}
		if target.Kind != "protocol-e2e" && target.Kind != "native-tests" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("unsupported Device Trust target kind %s: %s", id, target.Kind)
		}
		if strings.TrimSpace(target.OS) == "" || strings.TrimSpace(target.Arch) == "" || strings.TrimSpace(target.Runner) == "" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("incomplete Device Trust target: %s", id)
		}
		checks := map[string]bool{}
		for _, check := range target.RequiredChecks {
			if strings.TrimSpace(check) == "" || checks[check] {
				return releaseDeviceTrustCertification{}, fmt.Errorf("target %s содержит пустой/duplicate required check", id)
			}
			checks[check] = true
		}
		baseline := mandatoryNative
		if target.Kind == "protocol-e2e" {
			baseline = mandatoryProtocol
		}
		for check := range baseline {
			if !checks[check] {
				return releaseDeviceTrustCertification{}, fmt.Errorf("target %s ослабляет Device Trust Release: missing %s", id, check)
			}
		}
		targetByID[id] = target
		if target.Required {
			requiredIDs = append(requiredIDs, id)
			if target.Kind == "protocol-e2e" {
				requiredProtocol++
			} else {
				requiredNativeOS[strings.ToLower(target.OS)] = true
			}
		}
	}
	if len(requiredIDs) == 0 || requiredProtocol == 0 {
		return releaseDeviceTrustCertification{}, errors.New("Device Trust Release требует required PostgreSQL protocol target")
	}
	for _, osName := range []string{"linux", "windows", "macos"} {
		if !requiredNativeOS[osName] {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust Release требует required native target для %s", osName)
		}
	}

	resultByID := map[string]releaseDeviceTrustResult{}
	for _, result := range matrix.Targets {
		id := strings.TrimSpace(result.TargetID)
		if _, ok := targetByID[id]; !ok {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust matrix содержит unexpected target: %s", id)
		}
		if _, exists := resultByID[id]; exists {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust matrix содержит duplicate target: %s", id)
		}
		resultByID[id] = result
	}
	if len(resultByID) != len(targetByID) {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust matrix target count mismatch: expected=%d actual=%d", len(targetByID), len(resultByID))
	}

	passedIDs := []string{}
	for id, target := range targetByID {
		result := resultByID[id]
		if result.SchemaVersion != "1.0" || result.ProductVersion != ver || result.Status != "passed" || result.ExitCode != 0 {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust target %s не имеет валидный PASS/exitCode=0", id)
		}
		if result.Kind != target.Kind || result.OS != target.OS || result.Arch != target.Arch || strings.TrimSpace(result.RuntimeArch) == "" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust target %s identity mismatch между targets и matrix", id)
		}
		if result.Commit != matrix.Commit || result.RunID != matrix.RunID {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust target %s commit/runId не совпадает с aggregate matrix", id)
		}
		for _, check := range target.RequiredChecks {
			if result.Checks == nil || result.Checks[check] != true {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust target %s required check %s != true", id, check)
			}
		}
		if !deviceTrustSHA256RE.MatchString(strings.ToLower(result.EvidenceSHA256)) {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust target %s не содержит валидный evidenceSha256", id)
		}
		if target.Kind == "protocol-e2e" {
			if result.Claims == nil || result.Claims["repository"] != "postgresql" || result.Claims["vendorHardwareProvenance"] != "not-verified" || result.Claims["privateKeyServerExposed"] != false || result.Claims["deviceTrustRelease"] != ver {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust protocol target %s содержит неверные release/security claims", id)
			}
		} else {
			foundLimitation := false
			for _, limitation := range result.Limitations {
				if limitation == "headless-ci-does-not-prove-os-secure-storage-runtime" {
					foundLimitation = true
					break
				}
			}
			if !foundLimitation {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust native target %s скрывает headless CI limitation", id)
			}
			if result.Claims == nil || result.Claims["deviceTrustRelease"] != ver {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Device Trust native target %s не привязан к release %s", id, ver)
			}
		}
		passedIDs = append(passedIDs, id)
	}

	sort.Strings(requiredIDs)
	sort.Strings(passedIDs)
	matrixHash := sha256.Sum256(matrixRaw)
	targetsHash := sha256.Sum256(targetsRaw)
	return releaseDeviceTrustCertification{
		SchemaVersion: "1.0", ProductVersion: ver, CertifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Repository: matrix.Repository, Commit: matrix.Commit, RunID: matrix.RunID,
		MatrixSHA256: hex.EncodeToString(matrixHash[:]), TargetsSHA256: hex.EncodeToString(targetsHash[:]),
		RequiredTargetIDs: requiredIDs, PassedTargetIDs: passedIDs,
		Policy: "all-required-device-trust-targets-must-pass-exact-commit-evidence",
	}, nil
}

func verifyDeviceTrustCertificationInBundle(dir, ver string) error {
	matrixRaw, err := os.ReadFile(filepath.Join(dir, deviceTrustMatrixReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", deviceTrustMatrixReleaseFile, err)
	}
	targetsRaw, err := os.ReadFile(filepath.Join(dir, deviceTrustTargetsReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", deviceTrustTargetsReleaseFile, err)
	}
	certRaw, err := os.ReadFile(filepath.Join(dir, deviceTrustCertificationReleaseFile))
	if err != nil {
		return fmt.Errorf("%s missing: %w", deviceTrustCertificationReleaseFile, err)
	}
	var stored releaseDeviceTrustCertification
	if err := json.Unmarshal(certRaw, &stored); err != nil {
		return fmt.Errorf("%s invalid: %w", deviceTrustCertificationReleaseFile, err)
	}
	expected, err := validateDeviceTrustEvidence(matrixRaw, targetsRaw, ver, stored.Commit)
	if err != nil {
		return err
	}
	if stored.SchemaVersion != expected.SchemaVersion || stored.ProductVersion != expected.ProductVersion || stored.Repository != expected.Repository || stored.Commit != expected.Commit || stored.RunID != expected.RunID || stored.MatrixSHA256 != expected.MatrixSHA256 || stored.TargetsSHA256 != expected.TargetsSHA256 || stored.Policy != expected.Policy {
		return errors.New("DEVICE_TRUST_CERTIFICATION не соответствует embedded matrix/targets")
	}
	if strings.Join(stored.RequiredTargetIDs, "\x00") != strings.Join(expected.RequiredTargetIDs, "\x00") || strings.Join(stored.PassedTargetIDs, "\x00") != strings.Join(expected.PassedTargetIDs, "\x00") {
		return errors.New("DEVICE_TRUST_CERTIFICATION target sets mismatch")
	}
	return nil
}
