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
		t.Fatalf("unexpected certificate status/kind: %s %s", cert.Status, cert.Kind)
	}
	if cert.RequiredTargetCount != 292 || cert.PassedTargetCount != 292 {
		t.Fatalf("full RC target coverage=%d/%d, want 292/292", cert.PassedTargetCount, cert.RequiredTargetCount)
	}
	wantFamilies := map[string]int{"vanilla": 109, "fabric": 53, "quilt": 53, "forge": 50, "neoforge": 27}
	if len(cert.LoaderFamilies) != len(wantFamilies) {
		t.Fatalf("families=%d want=%d", len(cert.LoaderFamilies), len(wantFamilies))
	}
	for _, family := range cert.LoaderFamilies {
		want, ok := wantFamilies[family.Loader]
		if !ok {
			t.Fatalf("unexpected loader family %s", family.Loader)
		}
		if family.RequiredTargets != want || family.PassedTargets != want {
			t.Fatalf("%s coverage=%d/%d want=%d/%d", family.Loader, family.PassedTargets, family.RequiredTargets, want, want)
		}
		if len(family.EvidenceRootSHA256) != 64 {
			t.Fatalf("%s evidence root invalid: %s", family.Loader, family.EvidenceRootSHA256)
		}
	}
	if len(cert.Platforms) != 6 {
		t.Fatalf("platform coverage=%d want=6", len(cert.Platforms))
	}
	for name, passed := range cert.Invariants {
		if !passed {
			t.Fatalf("invariant %s=false", name)
		}
	}
	if !strings.HasPrefix(cert.CertificateID, "sha256:") || len(cert.CertificateID) != len("sha256:")+64 {
		t.Fatalf("invalid certificateId %q", cert.CertificateID)
	}
	if cert.Policy != "loader-compatibility-rc-0.17.11-full-release-certificate-all-292-targets-evidence-root-signed-bundle" {
		t.Fatalf("unexpected RC policy %s", cert.Policy)
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
		t.Fatalf("tampered RC root must fail closed, got %v", err)
	}
}

func TestLoaderCompatibilityReleaseCertificate01711RejectsMissingCertificate(t *testing.T) {
	bundle := writeLoaderCompatibilityRCFixture01711(t)
	if err := os.Remove(filepath.Join(bundle, loaderCompatibilityReleaseCertificateFile01711)); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompatibilityCertificationInBundle(bundle, "0.17.11"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing full RC must fail closed, got %v", err)
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
		t.Fatal("target evidence mutation must change full evidence root and certificate ID")
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
				t.Fatalf("RC release entry must be required/present: %#v", entry)
			}
		}
	}
	if !found {
		t.Fatal("full RC is missing from releaseBundleEntries")
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
		t.Fatal("full RC is missing from SHA256SUMS inputs")
	}
}
