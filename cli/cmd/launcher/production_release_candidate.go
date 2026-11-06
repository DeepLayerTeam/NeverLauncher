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

func productionReleaseCandidateRequiredGates01511(ver string) []string {
	gates := []string{
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
	if managedJavaIIRequired0165(ver) {
		gates = append(gates, "managed-java-II-8-16-17-21-25")
	}
	if compatibilityIIGa0170Required(ver) {
		gates = append(gates, "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base")
	}
	if windowsProtectionReleaseRequired01812(ver) {
		gates = append(gates, "windows-protection-rc-adversarial-signed-production-boundary")
	}
	if windowsProtectionGARequired0190(ver) {
		gates = append(gates, "windows-protection-ga-fail-closed-user-mode-boundary")
	}
	return gates
}

func normalizeSourceCommit01511(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !sourceCommitRE01511.MatchString(value) {
		return "", fmt.Errorf("Для промышленного релиз-кандидата требуется хеш исходного коммита из 40 или 64 шестнадцатеричных знаков; получено %q", value)
	}
	return value, nil
}

func releaseCandidateExcludedFile01511(name string) bool {
	switch name {
	case productionReleaseCandidateFile01511, productionDeliveryReleaseFile0160, "RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "PROVENANCE.json.sig":
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
			return nil, fmt.Errorf("Некорректное значение: путь к группе кандидатов на выпуск %q", name)
		}
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("Расчёт контрольной суммы набора кандидата релиза %s: %w", name, err)
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
		return "", fmt.Errorf("Некорректное значение: PROVENANCE.JSON: %w", err)
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
			return fmt.Errorf("Для промышленного релиз-кандидата требуется %s с точным идентификатором исходного коммита: %w", file, err)
		}
		if !strings.EqualFold(certCommit, commit) {
			return fmt.Errorf("Коммит исходников %s не совпадает: кандидат=%s, сертификация=%s", file, commit, certCommit)
		}
	}
	provCommit, err := provenanceSourceCommit01511(filepath.Join(dir, "PROVENANCE.json"))
	if err != nil {
		return fmt.Errorf("Коммит исходников в сведениях о происхождении производственного релиза: %w", err)
	}
	if !strings.EqualFold(provCommit, commit) {
		return fmt.Errorf("Несовпадение sourceCommit в PROVENANCE.json: кандидат=%s, происхождение=%s", commit, provCommit)
	}
	if err := verifyCompatibilityCertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Сертификация совместимости Minecraft: %w", err)
	}
	if err := verifyDeviceTrustCertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Сертификация доверия к устройствам: %w", err)
	}
	if err := verifyGuardCICertificationInBundle(dir, ver); err != nil {
		return fmt.Errorf("Межплатформенная сертификация Guard в CI: %w", err)
	}
	if err := verifyServerBridge2CertificationInBundle0150(dir, ver); err != nil {
		return fmt.Errorf("Ошибка сертификации ServerBridge: %w", err)
	}
	if err := verifyDeliveryManifest0151(dir, ver); err != nil {
		return fmt.Errorf("Манифест поставки: %w", err)
	}
	if err := verifyWindowsSigningEvidence0152(dir, ver, strict); err != nil {
		return fmt.Errorf("Производственная подпись Windows: %w", err)
	}
	if windowsProtectionReleaseRequired01812(ver) {
		if err := verifyWindowsProtectionRelease01812(dir, ver); err != nil {
			return fmt.Errorf("Сертификация RC защиты Windows: %w", err)
		}
	}
	if windowsProtectionGARequired0190(ver) {
		if err := verifyWindowsProtectionGA0190(dir, ver); err != nil {
			return fmt.Errorf("Сертификация GA защиты Windows: %w", err)
		}
	}
	if err := verifyLinuxProductionEvidence0153(dir, ver, true); err != nil {
		return fmt.Errorf("Производственные пакеты Linux: %w", err)
	}
	if err := verifyMacOSNotarizationEvidence0154(dir, ver, strict); err != nil {
		return fmt.Errorf("Нотариальное заверение производственного пакета macOS: %w", err)
	}
	if err := verifyManagedJREDistribution0155(dir, ver, true); err != nil {
		return fmt.Errorf("Доставка управляемой JRE: %w", err)
	}
	if err := verifyPublicProductionDeliveryMatrix0159(dir, ver); err != nil {
		return fmt.Errorf("Публичная матрица промышленной доставки: %w", err)
	}
	if _, err := loadReleaseTrustPolicy0158(filepath.Join(dir, releaseTrustPolicyFile0158)); err != nil {
		return fmt.Errorf("Политика доверия проверки релиза v2: %w", err)
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
		return errors.New("Пустое значение: группа кандидатов промышленного выпуска")
	}
	cert := productionReleaseCandidate01511{
		SchemaVersion: "1.0",
		Product:       "Launcher",
		Version:       ver,
		Status:        "production-release-candidate",
		SourceCommit:  commit,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		CohortSHA256:  productionReleaseCandidateCohortDigest01511(cohort),
		Cohort:        cohort,
		RequiredGates: productionReleaseCandidateRequiredGates01511(ver),
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
		return "", fmt.Errorf("Чтение: %s: %w", productionReleaseCandidateFile01511, err)
	}
	var cert productionReleaseCandidate01511
	if err := json.Unmarshal(raw, &cert); err != nil {
		return "", fmt.Errorf("Некорректное значение: %s: %w", productionReleaseCandidateFile01511, err)
	}
	commit, err := normalizeSourceCommit01511(cert.SourceCommit)
	if err != nil {
		return "", err
	}
	if cert.SchemaVersion != "1.0" || cert.Product != "Launcher" || cert.Version != ver || cert.Status != "production-release-candidate" {
		return "", errors.New("Несовпадение: метаданные кандидата промышленного выпуска")
	}
	if _, err := time.Parse(time.RFC3339, cert.CreatedAt); err != nil {
		return "", fmt.Errorf("Некорректное значение: дата создания кандидата промышленного выпуска: %w", err)
	}
	expectedGates := productionReleaseCandidateRequiredGates01511(ver)
	if len(cert.RequiredGates) != len(expectedGates) {
		return "", errors.New("Несовпадение: набор обязательных проверок кандидата промышленного выпуска")
	}
	for i := range expectedGates {
		if cert.RequiredGates[i] != expectedGates[i] {
			return "", fmt.Errorf("Проверка кандидата производственного релиза №%d не совпадает: ожидалось=%s, получено=%s", i+1, expectedGates[i], cert.RequiredGates[i])
		}
	}
	actualCohort, err := productionReleaseCandidateCohort01511(dir)
	if err != nil {
		return "", err
	}
	if len(actualCohort) != len(cert.Cohort) {
		return "", fmt.Errorf("Размер набора кандидата производственного релиза не совпадает: сертифицировано=%d, фактически=%d", len(cert.Cohort), len(actualCohort))
	}
	for i := range actualCohort {
		a, c := actualCohort[i], cert.Cohort[i]
		if a.Name != c.Name || a.Size != c.Size || !strings.EqualFold(a.SHA256, c.SHA256) {
			return "", fmt.Errorf("Набор кандидата производственного релиза не совпадает в %s", a.Name)
		}
	}
	digest := productionReleaseCandidateCohortDigest01511(actualCohort)
	if !strings.EqualFold(digest, strings.TrimSpace(cert.CohortSHA256)) {
		return "", errors.New("Несовпадение: контрольная сумма группы кандидатов промышленного выпуска (cohortSha256)")
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
