package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeReference0449(t *testing.T, base, class, run, project, source string, priv ed25519.PrivateKey) CohortInput {
	t.Helper()
	dir := filepath.Join(base, class)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{Format: format, Version: version, ReferenceClass: class, RunID: run, ProjectID: project, CommitSHA: testHash, SourceVersion: "5.7.4", TrustedGravitJarSHA256: testHash, TargetReleaseSHA256: testHash, ReportSHA256: testHash, SourceSHA256: source, ReviewedBy: "operator", ReviewEvidenceSHA256: testHash, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	for _, name := range requiredForClass(class) {
		raw := []byte("actual independent output for " + name)
		if name == "uuid-world-plugin-data" {
			raw, _ = json.Marshal(testStateAudit0450())
		}
		probe := Probe{RunID: run, Name: name, ReportSHA256: testHash, SourceSHA256: source, SourceVersion: "5.7.4", TargetReleaseSHA256: testHash, Passed: true, EvidenceFile: filepath.Join(dir, name+".evidence"), EvidenceSHA256: hash(raw)}
		if name == "uuid-world-plugin-data" {
			probe.SourceUUIDs = []string{testUUID}
			probe.TargetUUIDs = []string{testUUID}
			probe.SourceWorldSHA256 = testHash
			probe.TargetWorldSHA256 = testHash
			probe.SourcePluginSHA256 = testHash
			probe.TargetPluginSHA256 = testHash
		}
		encoded, err := json.Marshal(probe)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name+".receipt.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name+".evidence"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		bundle.Checks = append(bundle.Checks, SealedProbe{Name: name, SHA256: hash(encoded), EvidenceSHA256: hash(raw), ExecutableSHA256: testHash, DurationMS: 15})
	}
	cert, err := seal(bundle, priv)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, class+".certificate.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return CohortInput{Certificate: path, EvidenceDir: dir}
}
func TestAcceptanceCohort0449(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	trusted := filepath.Join(dir, "public.pem")
	if err = os.WriteFile(trusted, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cohort := map[string]CohortInput{}
	for i, class := range referenceClasses {
		cohort[class] = makeReference0449(t, dir, class, "migration-0000000"+string(rune('1'+i)), "project-"+class, hash([]byte(class)), priv)
	}
	if err := verifyCohort(trusted, cohort); err != nil {
		t.Fatal(err)
	}
	replaced := cohort["sql-modded"]
	cohort["sql-modded"] = cohort["fileauth-single"]
	if verifyCohort(trusted, cohort) == nil {
		t.Fatal("accepted duplicate project/incorrect cohort class")
	}
	cohort["sql-modded"] = replaced
	if err := os.Remove(filepath.Join(cohort["proxy-network"].EvidenceDir, "negative-rollback.evidence")); err != nil {
		t.Fatal(err)
	}
	if verifyCohort(trusted, cohort) == nil {
		t.Fatal("accepted absent negative rollback proof")
	}
}
func TestAcceptanceReceiptTampering0449(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := makeReference0449(t, dir, "fileauth-single", "migration-run-13", "project-13", testHash, priv)
	bundle, err := readCertificate(input.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidence(bundle, input.EvidenceDir); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(input.EvidenceDir, "negative-auth.receipt.json")
	if err := os.WriteFile(receipt, []byte(strings.Repeat("x", 30)), 0600); err != nil {
		t.Fatal(err)
	}
	if verifyEvidence(bundle, input.EvidenceDir) == nil {
		t.Fatal("forged negative auth report accepted")
	}
}
func TestEvidenceNoSymlink0449(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "actual.log")
	if err := os.WriteFile(source, []byte("real-log"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "stored")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := preserveEvidence(dest, "fileauth-login", link, hash([]byte("real-log")), []byte("{}")); err == nil {
		t.Fatal("symlink evidence accepted")
	}
	if err := preserveEvidence(dest, "fileauth-login", source, hash([]byte("other")), []byte("{}")); err == nil {
		t.Fatal("wrong SHA accepted")
	}
	if err := preserveEvidence(dest, "fileauth-login", source, hash([]byte("real-log")), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := preserveEvidence(dest, "fileauth-login", source, hash([]byte("real-log")), []byte("{}")); err == nil {
		t.Fatal("existing evidence overwritten")
	}
}

func TestMandatoryNegativeChecks0449(t *testing.T) {
	p := Plan{ReferenceClass: "sql-modded", Backend: "https://trusted.example", RunID: "migration-run-1", ProjectID: "project-1", SourceArchive: "/source.zip", CommitSHA: testHash, SourceVersion: "5.7.4", TrustedGravitJarSHA256: testHash, TargetReleaseSHA256: testHash, SigningKey: "/key", SnapshotSourceDir: "/source", SnapshotTargetDir: "/target"}
	for _, check := range requiredForClass(p.ReferenceClass) {
		p.Checks = append(p.Checks, Check{Name: check, ExecutableSHA256: testHash, Command: []string{"/usr/bin/probe"}, TimeoutSeconds: 10})
	}
	if err := validatePlan(p); err != nil {
		t.Fatal(err)
	}
	for i, check := range p.Checks {
		if check.Name == "negative-optional" {
			p.Checks = append(p.Checks[:i], p.Checks[i+1:]...)
			break
		}
	}
	if validatePlan(p) == nil {
		t.Fatal("missing required negative optional check")
	}
	p.ReferenceClass = "unknown"
	if validatePlan(p) == nil {
		t.Fatal("unknown reference project class accepted")
	}
}
