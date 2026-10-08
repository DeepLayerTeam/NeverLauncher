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
		return errors.New("доверие к устройству матрица путь пуст")
	}
	if strings.TrimSpace(targetsPath) == "" {
		return errors.New("доверие к устройству цели путь пуст")
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return fmt.Errorf("чтение Доверие к устройству матрица: %w", err)
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return fmt.Errorf("чтение Доверие к устройству цели: %w", err)
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
		return releaseDeviceTrustCertification{}, fmt.Errorf("DEVICE_TRUST_TARGETS недопустимый: %w", err)
	}
	var matrix releaseDeviceTrustMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		return releaseDeviceTrustCertification{}, fmt.Errorf("DEVICE_TRUST_MATRIX недопустимый: %w", err)
	}
	if targets.SchemaVersion != "1.0" || matrix.SchemaVersion != "1.0" {
		return releaseDeviceTrustCertification{}, errors.New("Доверие к устройству свидетельство требует schemaVersion=1.0")
	}
	if strings.TrimSpace(ver) == "" || targets.ProductVersion != ver || matrix.ProductVersion != ver {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству productVersion несоответствие: релиз=%s цели=%s матрица=%s", ver, targets.ProductVersion, matrix.ProductVersion)
	}
	if matrix.Status != "passed" || len(matrix.Errors) != 0 {
		return releaseDeviceTrustCertification{}, errors.New("Доверие к устройству матрица не имеет отказ с блокировкой состояние=пройден")
	}
	if strings.TrimSpace(matrix.Repository) == "" || strings.TrimSpace(matrix.Commit) == "" || strings.TrimSpace(matrix.RunID) == "" {
		return releaseDeviceTrustCertification{}, errors.New("Доверие к устройству матрица не содержит repository/commit/runId")
	}
	if strings.TrimSpace(expectedCommit) != "" && matrix.Commit != strings.TrimSpace(expectedCommit) {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству матрица фиксация несоответствие: ожидаемый=%s фактический=%s", strings.TrimSpace(expectedCommit), matrix.Commit)
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
			return releaseDeviceTrustCertification{}, errors.New("Доверие к устройству цель без ID")
		}
		if _, exists := targetByID[id]; exists {
			return releaseDeviceTrustCertification{}, fmt.Errorf("дубликат Доверие к устройству цель: %s", id)
		}
		if target.Kind != "protocol-e2e" && target.Kind != "native-tests" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("неподдерживаемый Доверие к устройству цель тип %s: %s", id, target.Kind)
		}
		if strings.TrimSpace(target.OS) == "" || strings.TrimSpace(target.Arch) == "" || strings.TrimSpace(target.Runner) == "" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("неполный Доверие к устройству цель: %s", id)
		}
		checks := map[string]bool{}
		for _, check := range target.RequiredChecks {
			if strings.TrimSpace(check) == "" || checks[check] {
				return releaseDeviceTrustCertification{}, fmt.Errorf("цель %s содержит пустой/дубликат обязательный проверка", id)
			}
			checks[check] = true
		}
		baseline := mandatoryNative
		if target.Kind == "protocol-e2e" {
			baseline = mandatoryProtocol
		}
		for check := range baseline {
			if !checks[check] {
				return releaseDeviceTrustCertification{}, fmt.Errorf("цель %s ослабляет Доверие к устройству Релиз: отсутствующий %s", id, check)
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
		return releaseDeviceTrustCertification{}, errors.New("Доверие к устройству Релиз требует обязательный PostgreSQL протокол цель")
	}
	for _, osName := range []string{"linux", "windows", "macos"} {
		if !requiredNativeOS[osName] {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству Релиз требует обязательный нативный цель для %s", osName)
		}
	}

	resultByID := map[string]releaseDeviceTrustResult{}
	for _, result := range matrix.Targets {
		id := strings.TrimSpace(result.TargetID)
		if _, ok := targetByID[id]; !ok {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству матрица содержит unexpected цель: %s", id)
		}
		if _, exists := resultByID[id]; exists {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству матрица содержит дубликат цель: %s", id)
		}
		resultByID[id] = result
	}
	if len(resultByID) != len(targetByID) {
		return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству матрица цель счётчик несоответствие: ожидаемый=%d фактический=%d", len(targetByID), len(resultByID))
	}

	passedIDs := []string{}
	for id, target := range targetByID {
		result := resultByID[id]
		if result.SchemaVersion != "1.0" || result.ProductVersion != ver || result.Status != "passed" || result.ExitCode != 0 {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству цель %s не имеет валидный PASS/exitCode=0", id)
		}
		if result.Kind != target.Kind || result.OS != target.OS || result.Arch != target.Arch || strings.TrimSpace(result.RuntimeArch) == "" {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству цель %s идентичность несоответствие между цели и матрица", id)
		}
		if result.Commit != matrix.Commit || result.RunID != matrix.RunID {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству цель %s commit/runId не совпадает с агрегат матрица", id)
		}
		for _, check := range target.RequiredChecks {
			if result.Checks == nil || result.Checks[check] != true {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству цель %s обязательный проверка %s!= true", id, check)
			}
		}
		if !deviceTrustSHA256RE.MatchString(strings.ToLower(result.EvidenceSHA256)) {
			return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству цель %s не содержит валидный evidenceSha256", id)
		}
		if target.Kind == "protocol-e2e" {
			if result.Claims == nil || result.Claims["repository"] != "postgresql" || result.Claims["vendorHardwareProvenance"] != "not-verified" || result.Claims["privateKeyServerExposed"] != false || result.Claims["deviceTrustRelease"] != ver {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству протокол цель %s содержит неверные release/security захватывает", id)
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
				return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству нативный цель %s скрывает headless CI limitation", id)
			}
			if result.Claims == nil || result.Claims["deviceTrustRelease"] != ver {
				return releaseDeviceTrustCertification{}, fmt.Errorf("Доверие к устройству нативный цель %s не привязан к релиз %s", id, ver)
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
		return fmt.Errorf("%s отсутствующий: %w", deviceTrustMatrixReleaseFile, err)
	}
	targetsRaw, err := os.ReadFile(filepath.Join(dir, deviceTrustTargetsReleaseFile))
	if err != nil {
		return fmt.Errorf("%s отсутствующий: %w", deviceTrustTargetsReleaseFile, err)
	}
	certRaw, err := os.ReadFile(filepath.Join(dir, deviceTrustCertificationReleaseFile))
	if err != nil {
		return fmt.Errorf("%s отсутствующий: %w", deviceTrustCertificationReleaseFile, err)
	}
	var stored releaseDeviceTrustCertification
	if err := json.Unmarshal(certRaw, &stored); err != nil {
		return fmt.Errorf("%s недопустимый: %w", deviceTrustCertificationReleaseFile, err)
	}
	expected, err := validateDeviceTrustEvidence(matrixRaw, targetsRaw, ver, stored.Commit)
	if err != nil {
		return err
	}
	if stored.SchemaVersion != expected.SchemaVersion || stored.ProductVersion != expected.ProductVersion || stored.Repository != expected.Repository || stored.Commit != expected.Commit || stored.RunID != expected.RunID || stored.MatrixSHA256 != expected.MatrixSHA256 || stored.TargetsSHA256 != expected.TargetsSHA256 || stored.Policy != expected.Policy {
		return errors.New("DEVICE_TRUST_CERTIFICATION не соответствует встроенный matrix/targets")
	}
	if strings.Join(stored.RequiredTargetIDs, "\x00") != strings.Join(expected.RequiredTargetIDs, "\x00") || strings.Join(stored.PassedTargetIDs, "\x00") != strings.Join(expected.PassedTargetIDs, "\x00") {
		return errors.New("DEVICE_TRUST_CERTIFICATION цель задаёт несоответствие")
	}
	return nil
}
