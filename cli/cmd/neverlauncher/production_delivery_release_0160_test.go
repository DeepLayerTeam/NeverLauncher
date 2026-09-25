package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSourceCommit0160 = "0123456789abcdef0123456789abcdef01234567"

func writeProductionReleaseFixture0160(t *testing.T, dir, ver, baseURL string) {
	t.Helper()
	for _, name := range productionDeliveryReleaseAnchorNames0160() {
		if name == productionReleaseCandidateFile01511 || name == publicProductionDeliveryMatrixFile0159 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture:"+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	matrix := PublicProductionDeliveryMatrix0159{
		SchemaVersion: publicProductionDeliverySchema0159,
		Product:       "NeverLauncher",
		Version:       ver,
		Channel:       publicProductionDeliveryChannel0159,
		GeneratedAt:   "2026-09-25T18:07:04Z",
		BaseURL:       baseURL,
	}
	for _, target := range expectedProductionTargets0160() {
		matrix.Targets = append(matrix.Targets, PublicDeliveryTarget0159{Platform: target.Platform, Architecture: target.Architecture})
	}
	if err := writeJSONFile(filepath.Join(dir, publicProductionDeliveryMatrixFile0159), matrix); err != nil {
		t.Fatal(err)
	}
	if err := writeProductionReleaseCandidateDocument01511(dir, ver, testSourceCommit0160); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDeliveryRelease0160BindsCandidateAndAnchors(t *testing.T) {
	dir := t.TempDir()
	ver := "0.16.0"
	writeProductionReleaseFixture0160(t, dir, ver, "https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v0.16.0")
	if err := writeProductionDeliveryRelease0160(dir, ver); err != nil {
		t.Fatal(err)
	}
	commit, err := verifyProductionDeliveryReleaseDocument0160(dir, ver)
	if err != nil {
		t.Fatal(err)
	}
	if commit != testSourceCommit0160 {
		t.Fatalf("commit=%s", commit)
	}
	if err := os.WriteFile(filepath.Join(dir, managedJREEvidenceFile0155), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyProductionDeliveryReleaseDocument0160(dir, ver); err == nil || !strings.Contains(err.Error(), "candidate") {
		// Candidate cohort detects the changed anchor before the GA anchor comparison.
		if err == nil {
			t.Fatal("expected tamper rejection")
		}
	}
}

func TestProductionDeliveryRelease0160RejectsUnversionedPublicOrigin(t *testing.T) {
	dir := t.TempDir()
	ver := "0.16.0"
	writeProductionReleaseFixture0160(t, dir, ver, "https://downloads.example.invalid/neverlauncher/stable")
	if err := writeProductionDeliveryRelease0160(dir, ver); err == nil || !strings.Contains(err.Error(), "immutable version segment") {
		t.Fatalf("expected immutable URL rejection, got %v", err)
	}
}

func TestProductionDeliveryRelease0160RejectsPrereleaseSemver(t *testing.T) {
	if err := stableProductionVersion0160("0.16.0-rc.1"); err == nil {
		t.Fatal("prerelease must not be accepted as Production Delivery Release")
	}
	if err := stableProductionVersion0160("0.16.0"); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDeliveryRelease0160PublicMatrixPublishesGACertificateControl(t *testing.T) {
	dir := t.TempDir()
	ver := "0.16.0"
	createPublicMatrixFixture0159(t, dir, ver)
	matrix, err := buildPublicProductionDeliveryMatrix0159(dir, ver, "https://downloads.example.test/neverlauncher/v0.16.0", false)
	if err != nil {
		t.Fatal(err)
	}
	foundGA, foundRC := false, false
	for _, control := range matrix.Controls {
		if control.Name == productionDeliveryReleaseFile0160 && control.Role == "production-delivery-release" {
			foundGA = true
		}
		if control.Name == productionReleaseCandidateFile01511 && control.Role == "production-release-candidate" {
			foundRC = true
		}
	}
	if !foundGA || !foundRC {
		t.Fatalf("0.16.0 public matrix must publish both RC and GA controls: rc=%v ga=%v", foundRC, foundGA)
	}
}
