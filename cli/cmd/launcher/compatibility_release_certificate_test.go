package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLoaderCompatibilityRCFixture01711(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.11", "commit-1711")
	matrixPath := filepath.Join(dir, "matrix.json")
	targetsPath := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetsPath, targetsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedCompatibilityCertification(bundle, matrixPath, targetsPath, "0.17.11", "commit-1711"); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestLoaderCompatibilityReleaseCertificate01711Complete(t *testing.T) {
	bundle := writeLoaderCompatibilityRCFixture01711(t)
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.17.11"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711))
	if err != nil {
		t.Fatal(err)
	}
	var cert loaderCompatibilityReleaseCertificate01711
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	if cert.Status != "certified" || cert.Kind != loaderCompatibilityReleaseCertificateKind01711 {
		t.Fatalf("Неожиданные статус или тип сертификата: %s %s", cert.Status, cert.Kind)
	}
	if cert.RequiredTargetCount != 292 || cert.PassedTargetCount != 292 {
		t.Fatalf("Покрытие целей релиз-кандидата=%d/%d, ожидается 292/292", cert.PassedTargetCount, cert.RequiredTargetCount)
	}
	wantFamilies := map[string]int{"vanilla": 109, "fabric": 53, "quilt": 53, "forge": 50, "neoforge": 27}
	if len(cert.LoaderFamilies) != len(wantFamilies) {
		t.Fatalf("families=%d want=%d", len(cert.LoaderFamilies), len(wantFamilies))
	}
	for _, family := range cert.LoaderFamilies {
		want, ok := wantFamilies[family.Loader]
		if !ok {
			t.Fatalf("неожиданное семейство загрузчиков %s", family.Loader)
		}
		if family.RequiredTargets != want || family.PassedTargets != want {
			t.Fatalf("%s coverage=%d/%d want=%d/%d", family.Loader, family.PassedTargets, family.RequiredTargets, want, want)
		}
		if len(family.EvidenceRootSHA256) != 64 {
			t.Fatalf("%s: недопустимый корневой каталог свидетельств: %s", family.Loader, family.EvidenceRootSHA256)
		}
	}
	if len(cert.Platforms) != 6 {
		t.Fatalf("Охват платформ=%d, ожидалось 6", len(cert.Platforms))
	}
	for name, passed := range cert.Invariants {
		if !passed {
			t.Fatalf("invariant %s=false", name)
		}
	}
	if !strings.HasPrefix(cert.CertificateID, "sha256:") || len(cert.CertificateID) != len("sha256:")+64 {
		t.Fatalf("Недопустимый идентификатор сертификата %q", cert.CertificateID)
	}
	if cert.Policy != "loader-compatibility-rc-0.17.11-full-release-certificate-all-292-targets-evidence-root-signed-bundle" {
		t.Fatalf("Неожиданная политика RC: %s", cert.Policy)
	}
}

func TestLoaderCompatibilityReleaseCertificate01711RejectsTamperedRoot(t *testing.T) {
	bundle := writeLoaderCompatibilityRCFixture01711(t)
	path := filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cert loaderCompatibilityReleaseCertificate01711
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	cert.EvidenceRootSHA256 = strings.Repeat("f", 64)
	raw, err = json.MarshalIndent(cert, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.17.11"); err == nil || !strings.Contains(err.Error(), "LOADER_COMPATIBILITY_RELEASE_CERTIFICATE") {
		t.Fatalf("Изменённый корень релиз-кандидата должен приводить к отказу: %v", err)
	}
}

func TestLoaderCompatibilityReleaseCertificate01711RejectsMissingCertificate(t *testing.T) {
	bundle := writeLoaderCompatibilityRCFixture01711(t)
	if err := os.Remove(filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711)); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.17.11"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Отсутствие полного релиз-кандидата должно приводить к отказу: %v", err)
	}
}

func TestLoaderCompatibilityReleaseCertificate01711EvidenceRootChanges(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.17.11", "commit-1711")
	cert1, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.17.11", "commit-1711")
	if err != nil {
		t.Fatal(err)
	}
	compatRaw1, err := json.Marshal(cert1)
	if err != nil {
		t.Fatal(err)
	}
	rc1, err := buildLoaderCompatibilityReleaseCertificate01711(matrixRaw, targetsRaw, compatRaw1, cert1)
	if err != nil {
		t.Fatal(err)
	}
	var matrix releaseCompatibilityMatrix
	if err := json.Unmarshal(matrixRaw, &matrix); err != nil {
		t.Fatal(err)
	}
	matrix.Targets[0].EvidenceSHA256 = strings.Repeat("e", 64)
	matrixRaw2, _ := json.Marshal(matrix)
	cert2, err := validateCompatibilityEvidence(matrixRaw2, targetsRaw, "0.17.11", "commit-1711")
	if err != nil {
		t.Fatal(err)
	}
	compatRaw2, err := json.Marshal(cert2)
	if err != nil {
		t.Fatal(err)
	}
	rc2, err := buildLoaderCompatibilityReleaseCertificate01711(matrixRaw2, targetsRaw, compatRaw2, cert2)
	if err != nil {
		t.Fatal(err)
	}
	if rc1.EvidenceRootSHA256 == rc2.EvidenceRootSHA256 || rc1.CertificateID == rc2.CertificateID {
		t.Fatal("Изменение подтверждений цели должно менять общий корень доказательств и идентификатор сертификата")
	}
}

func TestLoaderCompatibilityReleaseCertificate01711IsRequiredReleaseEntryAndChecksum(t *testing.T) {
	bundle := writeLoaderCompatibilityRCFixture01711(t)
	entries := releaseBundleEntries("0.17.11", bundle)
	found := false
	for _, entry := range entries {
		if entry["name"] == loaderCompatibilityReleaseCertificateFile01711 {
			found = true
			if entry["required"] != true || entry["status"] != "present" {
				t.Fatalf("Запись релиза RC должна быть обязательной и присутствовать: %#v", entry)
			}
		}
	}
	if !found {
		t.Fatal("полный кандидат в релиз отсутствует в releaseBundleEntries")
	}
	checksums, err := releaseChecksums(bundle)
	if err != nil {
		t.Fatal(err)
	}
	checksumFound := false
	for _, line := range checksums {
		if strings.HasSuffix(line, "  "+loaderCompatibilityReleaseCertificateFile01711) {
			checksumFound = true
			break
		}
	}
	if !checksumFound {
		t.Fatal("Полный релиз-кандидат отсутствует среди входных данных SHA256SUMS")
	}
}

func TestLoaderCompatibilityGA0180CertificateBindsRuntimeSupport(t *testing.T) {
	dir := t.TempDir()
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.18.0", "commit-180")
	matrixPath := filepath.Join(dir, "matrix.json")
	targetsPath := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetsPath, targetsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedCompatibilityCertification(bundle, matrixPath, targetsPath, "0.18.0", "commit-180"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.18.0"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711))
	if err != nil {
		t.Fatal(err)
	}
	var cert loaderCompatibilityReleaseCertificate01711
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	if cert.Status != "ga-certified" || cert.ReleaseStage != "ga" {
		t.Fatalf("Неожиданные статус или этап GA: %s/%s", cert.Status, cert.ReleaseStage)
	}
	if cert.RuntimeSupportEntries != 163 || cert.RuntimeSupportSHA256 != loaderGASupportSHA2560180() {
		t.Fatalf("Несоответствие привязки поддержки Runtime к GA: записей=%d sha=%s", cert.RuntimeSupportEntries, cert.RuntimeSupportSHA256)
	}
	if strings.Join(cert.LegacyForgeVersions, ",") != "1.7.10,1.12.2" {
		t.Fatalf("Несовпадение данных GA для старой версии Forge: %v", cert.LegacyForgeVersions)
	}
	if !cert.Invariants["gaRuntimeSupportEnforced"] || !cert.Invariants["legacyForgeGA"] {
		t.Fatalf("отсутствуют обязательные условия приёмки GA: %+v", cert.Invariants)
	}
	if cert.Policy != "loader-compatibility-ga-0.18.0-runtime-enforced-fabric-quilt-forge-neoforge-legacy-all-292-targets-signed-bundle" {
		t.Fatalf("Неожиданная политика GA: %s", cert.Policy)
	}
}

func TestLoaderCompatibilityGA0180RejectsCertifiedRuntimeSurfaceDrift(t *testing.T) {
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.18.0", "commit-180")
	var targets releaseCompatibilityTargets
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		t.Fatal(err)
	}
	for i := range targets.Targets {
		if targets.Targets[i].Loader == "forge" && targets.Targets[i].Minecraft == "1.12.2" {
			targets.Targets[i].Minecraft = "1.12.1"
			break
		}
	}
	targetsRaw, _ = json.Marshal(targets)
	if _, err := validateCompatibilityEvidence(matrixRaw, targetsRaw, "0.18.0", "commit-180"); err == nil {
		t.Fatal("Подтверждения совместимости GA должны отклонять отклонения поддержки устаревшего Forge")
	}
}

func TestLoaderCompatibilityGA0180RejectsTamperedRuntimeSupportHash(t *testing.T) {
	dir := t.TempDir()
	matrixRaw, targetsRaw := vanillaBaselineIIEvidenceFixture(t, "0.18.0", "commit-180")
	matrixPath := filepath.Join(dir, "matrix.json")
	targetsPath := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(matrixPath, matrixRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetsPath, targetsRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := embedCompatibilityCertification(bundle, matrixPath, targetsPath, "0.18.0", "commit-180"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cert loaderCompatibilityReleaseCertificate01711
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	cert.RuntimeSupportSHA256 = strings.Repeat("a", 64)
	raw, _ = json.MarshalIndent(cert, "", "  ")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.18.0"); err == nil {
		t.Fatal("Изменённый хеш поддержки Runtime GA должен приводить к отказу")
	}
}
