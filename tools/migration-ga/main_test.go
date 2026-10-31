package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

func sampleReport(t *testing.T, source string) Report {
	t.Helper()
	r := Report{Format: "launcher.gravit-migration-report.v1", RunID: "abcdef0123456789", ProjectID: "project-1", SourceSHA256: source, InventorySHA256: testHash, RunRevision: 2, Items: []Item{}, Identities: []Identity{{Provider: "fileauth", SourceID: "1", Username: "player", UUID: testUUID, TargetUserID: "player", Status: "imported"}}, Evidence: []Evidence{}, Decisions: []Decision{}, Counts: map[string]int{"transferred": 0, "transformed": 0, "manual": 0, "blocked": 0}, Blockers: []string{}, Status: "review_required"}
	for _, stage := range []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"} {
		r.Evidence = append(r.Evidence, Evidence{Stage: stage, State: "verified", SHA256: testHash})
	}
	r.Evidence = append(r.Evidence, Evidence{Stage: "cutover_scope:default/stable", State: "verified", SHA256: testHash, Details: "active"})
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	r.ReportSHA256 = hash(b)
	return r
}
func TestReportIntegrityAndCutover(t *testing.T) {
	r := sampleReport(t, testHash)
	if e := reportVerified(r); e != nil {
		t.Fatal(e)
	}
	r.ReportSHA256 = testHash
	if reportVerified(r) == nil {
		t.Fatal("spoofed digest accepted")
	}
	r = sampleReport(t, testHash)
	r.Evidence[len(r.Evidence)-1].Details = "cancelled"
	r.ReportSHA256 = ""
	b, _ := json.Marshal(r)
	r.ReportSHA256 = hash(b)
	if reportVerified(r) == nil {
		t.Fatal("cancelled migration accepted")
	}
}
func TestCheckPlanRequiresFullMatrix(t *testing.T) {
	p := Plan{Backend: "https://trusted.example", RunID: "abcdef0123456789", ProjectID: "p", SourceArchive: "/s.zip", CommitSHA: testHash, SourceVersion: "5.7.4", TrustedGravitJarSHA256: trustedJarHash(t), TargetReleaseSHA256: testHash, SigningKey: "/key"}
	if validatePlan(p) == nil {
		t.Fatal("accepted absent E2E checks")
	}
	for _, n := range required {
		p.Checks = append(p.Checks, Check{Name: n, Command: []string{"true"}, TimeoutSeconds: 10})
	}
	if e := validatePlan(p); e != nil {
		t.Fatal(e)
	}
	p.Checks[0].Command = nil
	if validatePlan(p) == nil {
		t.Fatal("accepted no execution")
	}
}
func TestGAProbeHelper(t *testing.T) {
	if os.Getenv("NEVER_GA_PROBE_HELPER") != "1" {
		return
	}
	if os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN") != "" || os.Getenv("MIGRATION_GA_SIGNING_KEY_B64") != "" {
		os.Exit(9)
	}
	epath := os.Getenv("NEVER_GA_PROBE_EVIDENCE")
	// The helper updates the receipt during this process invocation.
	_ = os.Chtimes(epath, time.Now(), time.Now())
	name := ""
	if len(os.Args) >= 2 {
		name = os.Args[len(os.Args)-1]
	}
	p := Probe{RunID: os.Getenv("NEVER_GA_RUN"), Name: name, Passed: true, ReportSHA256: os.Getenv("NEVER_GA_REPORT"), SourceSHA256: os.Getenv("NEVER_GA_SOURCE"), SourceVersion: "5.7.4", TargetReleaseSHA256: testHash, EvidenceFile: epath, EvidenceSHA256: os.Getenv("NEVER_GA_EVIDENCE_HASH")}
	if p.Name == "uuid-world-plugin-data" {
		p.SourceUUIDs = []string{testUUID}
		p.TargetUUIDs = []string{testUUID}
		p.SourceWorldSHA256 = testHash
		p.TargetWorldSHA256 = testHash
		p.SourcePluginSHA256 = testHash
		p.TargetPluginSHA256 = testHash
	}
	b, _ := json.Marshal(p)
	fmt.Println(string(b))
	os.Exit(0)
}
func createSourceZIP(t *testing.T) []byte {
	t.Helper()
	var inner bytes.Buffer
	writer := zip.NewWriter(&inner)
	f, e := writer.Create("META-INF/MANIFEST.MF")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.Write([]byte("Manifest-Version: 1.0\r\nImplementation-Title: GravitLauncher LaunchServer\r\nImplementation-Version: 5.7.4\r\n"))
	if e != nil {
		t.Fatal(e)
	}
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	var outer bytes.Buffer
	w := zip.NewWriter(&outer)
	jar, e := w.Create("gravit/LaunchServer.jar")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = jar.Write(inner.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return outer.Bytes()
}
func TestCertifyExecutesChecksAndSigns(t *testing.T) {
	dir := t.TempDir()
	sourceFile := filepath.Join(dir, "src.zip")
	if e := os.WriteFile(sourceFile, createSourceZIP(t), 0600); e != nil {
		t.Fatal(e)
	}
	sourceDigest, e := shaFile(sourceFile, 1024)
	if e != nil {
		t.Fatal(e)
	}
	r := sampleReport(t, sourceDigest)
	review := Review{Report: r, ReviewedBy: "operator", EvidenceSHA256: testHash, EvidenceReference: "immutable-ci-ref", Status: "rc_reviewed_not_ga_certified"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "access denied", 403)
			return
		}
		if strings.HasSuffix(req.URL.Path, "/review") {
			json.NewEncoder(w).Encode(map[string]any{"data": review})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"data": r})
		}
	}))
	defer server.Close()
	_, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	keyFile := filepath.Join(dir, "signer.pem")
	if e = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	evidenceFile := filepath.Join(dir, "real-check-evidence")
	if e = os.WriteFile(evidenceFile, []byte("isolated-check-output"), 0600); e != nil {
		t.Fatal(e)
	}
	evidenceHash, e := shaFile(evidenceFile, 1024)
	if e != nil {
		t.Fatal(e)
	}
	p := Plan{Backend: server.URL, RunID: r.RunID, ProjectID: r.ProjectID, SourceArchive: sourceFile, CommitSHA: testHash, SourceVersion: "5.7.4", TrustedGravitJarSHA256: trustedJarHash(t), TargetReleaseSHA256: testHash, SigningKey: keyFile}
	for _, name := range required {
		p.Checks = append(p.Checks, Check{Name: name, Command: []string{os.Args[0], "-test.run=TestGAProbeHelper"}, TimeoutSeconds: 10})
	}
	t.Setenv("LAUNCHER_MIGRATION_GA_TOKEN", "high-privilege-secret")
	t.Setenv("MIGRATION_GA_SIGNING_KEY_B64", "high-privilege-key")
	for _, env := range []string{"NEVER_GA_PROBE_HELPER=1", "NEVER_GA_RUN=" + r.RunID, "NEVER_GA_REPORT=" + r.ReportSHA256, "NEVER_GA_SOURCE=" + r.SourceSHA256, "NEVER_GA_EVIDENCE_HASH=" + evidenceHash, "NEVER_GA_PROBE_EVIDENCE=" + evidenceFile} {
		kv := strings.SplitN(env, "=", 2)
		t.Setenv(kv[0], kv[1])
	}
	// Commands are static per check, so use a wrapper that identifies the check
	// via a positional environment variable passed to the helper executable.
	for i := range p.Checks {
		p.Checks[i].Command = append(p.Checks[i].Command, "--", p.Checks[i].Name)
	}
	output := filepath.Join(dir, "certificate.json")
	if e = certify(context.Background(), p, "secret", output); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	var b Bundle
	if e = decodeStrict(data, &b); e != nil {
		t.Fatal(e)
	}
	if len(b.Checks) != len(required) {
		t.Fatal("missing GA checks")
	}
	if e = verifyBundle(b, priv.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
	b.SourceSHA256 = testHash
	if verifyBundle(b, priv.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("tampered certificate accepted")
	}
	if _, e = os.Stat(output); e != nil {
		t.Fatal(e)
	}
}
func TestDigestAndURLValidation(t *testing.T) {
	if _, e := hex.DecodeString(testHash); e != nil {
		t.Fatal(e)
	}
	for _, url := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/a", "https://example.com?secret=1"} {
		if checkBackendURL(url) == nil {
			t.Fatalf("unsafe backend %s accepted", url)
		}
	}
	for _, url := range []string{"http://127.0.0.1:9080", "https://example.com"} {
		if e := checkBackendURL(url); e != nil {
			t.Fatal(e)
		}
	}
}

func trustedJarHash(t *testing.T) string {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(createSourceZIP(t)), int64(len(createSourceZIP(t))))
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range z.File {
		if filepath.Base(f.Name) != "LaunchServer.jar" {
			continue
		}
		rd, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(rd)
		rd.Close()
		if e != nil {
			t.Fatal(e)
		}
		return hash(b)
	}
	t.Fatal("fixture has no LaunchServer.jar")
	return ""
}
func TestSourceVersionPinnedToRealJAR0340(t *testing.T) {
	p := filepath.Join(t.TempDir(), "source.zip")
	if e := os.WriteFile(p, createSourceZIP(t), 0600); e != nil {
		t.Fatal(e)
	}
	v, e := sourceJarVersion(p)
	if e != nil || v != "5.7.4" {
		t.Fatalf("actual jar version: %q %v", v, e)
	}
	if e = os.WriteFile(p, []byte("not an archive"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = sourceJarVersion(p); e == nil {
		t.Fatal("accepted malformed source ZIP")
	}
}

func TestAtomicPrivateCertificateNoOverwrite0340(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	if e := writePrivate(path, []byte("proof-one")); e != nil {
		t.Fatal(e)
	}
	if e := writePrivate(path, []byte("proof-two")); e == nil {
		t.Fatal("certificate overwrite succeeded")
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "proof-one" {
		t.Fatal("overwritten or missing certificate", e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("not owner-only", e)
	}
}
func TestRejectInsecureKey0340(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.pem")
	if e := os.WriteFile(path, []byte("secret"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := signingKey(path); e == nil {
		t.Fatal("world-readable key accepted")
	}
}
