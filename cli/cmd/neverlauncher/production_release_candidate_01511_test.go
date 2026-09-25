package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSourceCommit01511 = "0123456789abcdef0123456789abcdef01234567"

func TestProductionReleaseCandidateRequired01511(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"0.15.10", false},
		{"0.15.11", true},
		{"0.16.0", true},
	}
	for _, tc := range cases {
		if got := productionReleaseCandidateRequired01511(tc.version); got != tc.want {
			t.Fatalf("productionReleaseCandidateRequired01511(%q)=%v want=%v", tc.version, got, tc.want)
		}
	}
}

func TestProductionReleaseCandidate01511BindsExactCohort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "artifact-a.bin"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact-b.bin"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeProductionReleaseCandidateDocument01511(dir, "0.15.11", testSourceCommit01511); err != nil {
		t.Fatal(err)
	}
	commit, err := verifyProductionReleaseCandidateDocument01511(dir, "0.15.11")
	if err != nil {
		t.Fatal(err)
	}
	if commit != testSourceCommit01511 {
		t.Fatalf("source commit=%s", commit)
	}
	// Signature envelopes are produced after candidate certification and are intentionally outside the pre-sign cohort.
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte("signature"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyProductionReleaseCandidateDocument01511(dir, "0.15.11"); err != nil {
		t.Fatalf("post-certification signature file must not change cohort: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact-a.bin"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyProductionReleaseCandidateDocument01511(dir, "0.15.11"); err == nil || !strings.Contains(err.Error(), "cohort mismatch") {
		t.Fatalf("tampered cohort accepted: %v", err)
	}
}

func TestProductionReleaseCandidate01511RejectsInjectedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "artifact.bin"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeProductionReleaseCandidateDocument01511(dir, "0.15.11", testSourceCommit01511); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "injected.bin"), []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyProductionReleaseCandidateDocument01511(dir, "0.15.11"); err == nil || !strings.Contains(err.Error(), "cohort size mismatch") {
		t.Fatalf("injected post-certification file accepted: %v", err)
	}
}

func TestSLSAProvenance01511CarriesExactSourceCommit(t *testing.T) {
	artifacts := t.TempDir()
	if err := os.WriteFile(filepath.Join(artifacts, "artifact.bin"), []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	prov, err := slsaProvenance(".", artifacts, "0.15.11", testSourceCommit01511)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "PROVENANCE.json")
	if err := writeJSONFile(path, prov); err != nil {
		t.Fatal(err)
	}
	commit, err := provenanceSourceCommit01511(path)
	if err != nil {
		t.Fatal(err)
	}
	if commit != testSourceCommit01511 {
		t.Fatalf("provenance source commit=%s", commit)
	}
}

func TestNormalizeSourceCommit01511RejectsPlaceholders(t *testing.T) {
	for _, value := range []string{"", "HEAD", "deadbeef", strings.Repeat("g", 40)} {
		if _, err := normalizeSourceCommit01511(value); err == nil {
			t.Fatalf("invalid source commit accepted: %q", value)
		}
	}
}
