// Migration Center GA evidence runner. This binary does not declare a deployment
// production-ready merely because an administrator reviewed a migration report:
// it executes the configured independent checks and seals their actual output.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "0.34.0"
const format = "launcher.gravit-ga-execution.v1"
const maxDocument = 32 << 20

var gravit57 = regexp.MustCompile(`^5\.7\.[0-9]+$`)

var required = []string{
	"fileauth-login", "sql-login", "official-login", "forge-launch-join", "neoforge-launch-join",
	"optional-presets", "skins", "uuid-world-plugin-data", "admin-permissions", "serverwrapper",
	"desktop-cache-install", "staged-cutover-canary", "operational-rollback-drill",
}

type Item struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}
type Identity struct {
	Provider     string `json:"provider"`
	SourceID     string `json:"sourceId"`
	Username     string `json:"username"`
	UUID         string `json:"uuid"`
	TargetUserID string `json:"targetUserId,omitempty"`
	Status       string `json:"status"`
}
type Evidence struct {
	Stage   string `json:"stage"`
	SHA256  string `json:"sha256,omitempty"`
	State   string `json:"state"`
	Details string `json:"details,omitempty"`
}
type Decision struct {
	Sequence int64  `json:"sequence"`
	Kind     string `json:"kind"`
	Revision int64  `json:"revision"`
}

// This mirrors the backend's v1 report wire schema, including Go's canonical
// struct field order, so a receipt cannot be rebound to an altered report.
type Report struct {
	Format          string         `json:"format"`
	RunID           string         `json:"runId"`
	ProjectID       string         `json:"projectId"`
	SourceSHA256    string         `json:"sourceSha256,omitempty"`
	InventorySHA256 string         `json:"inventorySha256,omitempty"`
	RunRevision     int64          `json:"runRevision"`
	Items           []Item         `json:"items"`
	Identities      []Identity     `json:"identities"`
	Evidence        []Evidence     `json:"evidence"`
	Decisions       []Decision     `json:"operatorDecisions"`
	Counts          map[string]int `json:"counts"`
	Blockers        []string       `json:"blockers"`
	Status          string         `json:"status"`
	ReportSHA256    string         `json:"reportSha256"`
}
type Review struct {
	Report            Report `json:"report"`
	ReviewedBy        string `json:"reviewedBy"`
	EvidenceSHA256    string `json:"evidenceSha256"`
	EvidenceReference string `json:"evidenceReference"`
	ReviewedAt        string `json:"reviewedAt"`
	Status            string `json:"status"`
}
type Check struct {
	Name           string   `json:"name"`
	Command        []string `json:"command"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}
type Plan struct {
	Backend                string  `json:"backend"`
	RunID                  string  `json:"runId"`
	ProjectID              string  `json:"projectId"`
	SourceArchive          string  `json:"sourceArchive"`
	CommitSHA              string  `json:"commitSha"`
	SourceVersion          string  `json:"sourceVersion"`
	TrustedGravitJarSHA256 string  `json:"trustedGravitJarSha256"`
	TargetReleaseSHA256    string  `json:"targetReleaseSha256"`
	SigningKey             string  `json:"signingKey"`
	Checks                 []Check `json:"checks"`
}
type Probe struct {
	RunID               string   `json:"runId"`
	Name                string   `json:"name"`
	ReportSHA256        string   `json:"reportSha256"`
	SourceSHA256        string   `json:"sourceSha256"`
	SourceVersion       string   `json:"sourceVersion"`
	TargetReleaseSHA256 string   `json:"targetReleaseSha256"`
	Passed              bool     `json:"passed"`
	EvidenceFile        string   `json:"evidenceFile"`
	EvidenceSHA256      string   `json:"evidenceSha256"`
	SourceUUIDs         []string `json:"sourceUuids,omitempty"`
	TargetUUIDs         []string `json:"targetUuids,omitempty"`
	SourceWorldSHA256   string   `json:"sourceWorldSha256,omitempty"`
	TargetWorldSHA256   string   `json:"targetWorldSha256,omitempty"`
	SourcePluginSHA256  string   `json:"sourcePluginSha256,omitempty"`
	TargetPluginSHA256  string   `json:"targetPluginSha256,omitempty"`
}
type SealedProbe struct {
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	DurationMS     int64  `json:"durationMs"`
}
type Bundle struct {
	Format                 string        `json:"format"`
	Version                string        `json:"version"`
	RunID                  string        `json:"runId"`
	ProjectID              string        `json:"projectId"`
	CommitSHA              string        `json:"commitSha"`
	SourceVersion          string        `json:"sourceVersion"`
	TrustedGravitJarSHA256 string        `json:"trustedGravitJarSha256"`
	TargetReleaseSHA256    string        `json:"targetReleaseSha256"`
	ReportSHA256           string        `json:"reportSha256"`
	SourceSHA256           string        `json:"sourceSha256"`
	ReviewedBy             string        `json:"reviewedBy"`
	ReviewEvidenceSHA256   string        `json:"reviewEvidenceSha256"`
	CompletedAt            string        `json:"completedAt"`
	Checks                 []SealedProbe `json:"checks"`
	PublicKey              string        `json:"publicKey"`
	Signature              string        `json:"signature"`
}

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func commitHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func decodeStrict(data []byte, v any) error {
	if len(data) == 0 || len(data) > maxDocument {
		return errors.New("empty or oversized JSON document")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if e := d.Decode(&extra); !errors.Is(e, io.EOF) {
		return errors.New("trailing JSON document")
	}
	return nil
}
func shaFile(path string, limit int64) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return "", e
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > limit {
		return "", errors.New("evidence must be a nonempty bounded regular file")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil {
		return "", e
	}
	if n != st.Size() {
		return "", errors.New("evidence changed while reading")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func reportVerified(r Report) error {
	if r.Format != "launcher.gravit-migration-report.v1" || r.Status != "review_required" || len(r.Blockers) != 0 || !digest(r.SourceSHA256) || !digest(r.InventorySHA256) || !digest(r.ReportSHA256) || len(r.Identities) == 0 {
		return errors.New("migration report is blocked or incomplete")
	}
	d := r.ReportSHA256
	r.ReportSHA256 = ""
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if hash(b) != d {
		return errors.New("migration report checksum mismatch")
	}
	stages := map[string]string{}
	for _, ev := range r.Evidence {
		if _, ok := stages[ev.Stage]; ok {
			return errors.New("duplicate report stage")
		}
		stages[ev.Stage] = ev.State
	}
	for _, n := range []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"} {
		if stages[n] != "verified" {
			return fmt.Errorf("migration stage %s not verified", n)
		}
	}
	active := false
	for n, s := range stages {
		if strings.HasPrefix(n, "cutover_scope:") && s == "verified" {
			for _, ev := range r.Evidence {
				if ev.Stage == n && ev.Details == "active" {
					active = true
				}
			}
		}
	}
	if !active {
		return errors.New("no active validated migration cutover scope")
	}
	for _, id := range r.Identities {
		if id.Status != "imported" && id.Status != "matched" || id.TargetUserID == "" {
			return errors.New("unresolved migrated identity")
		}
	}
	return nil
}
func getJSON(ctx context.Context, client *http.Client, endpoint, token string, out any) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("migration backend returned HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxDocument+1))
	if e != nil {
		return e
	}
	// All Launcher Admin responses are enveloped as {"data": ...}.
	// Do not accept a bare or unknown response that only happens to match a
	// subset of the expected report fields.
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := decodeStrict(b, &envelope); err != nil {
		return err
	}
	return decodeStrict(envelope.Data, out)
}
func checkBackendURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil {
		return e
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Host == "" {
		return errors.New("backend URL must contain only its origin")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return errors.New("HTTPS required except for numeric loopback")
	}
	return nil
}

// sourceJarVersion verifies the actual LaunchServer binary contained in MIG03,
// not the operator's version claim. This intentionally accepts only manifests
// carrying an explicit Gravit/LaunchServer product identity.
func sourceJarEvidence(archivePath string) (string, string, error) {
	outer, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", "", err
	}
	defer outer.Close()
	if len(outer.File) > 30000 {
		return "", "", errors.New("too many source ZIP entries")
	}
	found := ""
	jarHash := ""
	for _, f := range outer.File {
		if !strings.EqualFold(path.Base(f.Name), "LaunchServer.jar") {
			continue
		}
		if found != "" {
			return "", "", errors.New("multiple LaunchServer jars")
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > 32<<20 || f.CompressedSize64 == 0 {
			return "", "", errors.New("unsafe LaunchServer jar size")
		}
		reader, e := f.Open()
		if e != nil {
			return "", "", e
		}
		data, e := io.ReadAll(io.LimitReader(reader, (32<<20)+1))
		reader.Close()
		if e != nil || uint64(len(data)) != f.UncompressedSize64 {
			return "", "", errors.New("unreadable LaunchServer jar")
		}
		nested, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return "", "", e
		}
		if len(nested.File) > 20000 {
			return "", "", errors.New("excessive jar entries")
		}
		var manifest string
		for _, item := range nested.File {
			if !strings.EqualFold(item.Name, "META-INF/MANIFEST.MF") {
				continue
			}
			if manifest != "" || item.UncompressedSize64 > 64<<10 {
				return "", "", errors.New("duplicate/oversized jar manifest")
			}
			read, e := item.Open()
			if e != nil {
				return "", "", e
			}
			b, e := io.ReadAll(io.LimitReader(read, (64<<10)+1))
			read.Close()
			if e != nil || uint64(len(b)) != item.UncompressedSize64 {
				return "", "", errors.New("invalid jar manifest")
			}
			manifest = string(b)
		}
		if manifest == "" {
			return "", "", errors.New("missing LaunchServer jar manifest")
		}
		product := ""
		ver := ""
		for _, line := range strings.Split(strings.ReplaceAll(manifest, "\r\n", "\n"), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			switch k {
			case "implementation-title", "bundle-name", "implementation-vendor":
				product += " " + strings.ToLower(v)
			case "implementation-version", "bundle-version":
				if ver == "" {
					ver = v
				}
			}
		}
		if !strings.Contains(product, "gravit") && !strings.Contains(product, "launchserver") {
			return "", "", errors.New("JAR is not verifiably Gravit LaunchServer")
		}
		jarHash = hash(data)
		ver = strings.TrimPrefix(ver, "v")
		if !gravit57.MatchString(ver) {
			return "", "", errors.New("unsupported JAR version")
		}
		found = ver
	}
	if found == "" {
		return "", "", errors.New("LaunchServer JAR absent")
	}
	return found, jarHash, nil
}

func sourceJarVersion(archivePath string) (string, error) {
	version, _, err := sourceJarEvidence(archivePath)
	return version, err
}

func validatePlan(p Plan) error {
	if err := checkBackendURL(p.Backend); err != nil {
		return err
	}
	parts := strings.Split(p.SourceVersion, ".")
	patch := -1
	if len(parts) == 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	if len(p.RunID) < 8 || len(p.RunID) > 128 || p.ProjectID == "" || !commitHash(p.CommitSHA) || !gravit57.MatchString(p.SourceVersion) || patch < 0 || patch > 12 || !digest(p.TrustedGravitJarSHA256) || !digest(p.TargetReleaseSHA256) || p.SigningKey == "" || p.SourceArchive == "" {
		return errors.New("missing/invalid run, project, source, signing key or commit SHA-256")
	}
	if !filepath.IsAbs(p.SourceArchive) || !filepath.IsAbs(p.SigningKey) {
		return errors.New("source archive and signer key paths must be absolute")
	}
	if githubSHA := os.Getenv("GITHUB_SHA"); githubSHA != "" && githubSHA != p.CommitSHA {
		return errors.New("plan commit differs from checked-out CI commit")
	}
	if len(p.Checks) != len(required) {
		return fmt.Errorf("exactly %d independently executed GA checks are required", len(required))
	}
	seen := map[string]bool{}
	for _, c := range p.Checks {
		if seen[c.Name] || len(c.Command) == 0 || c.Command[0] == "" || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 900 {
			return errors.New("duplicate/invalid check command")
		}
		seen[c.Name] = true
	}
	for _, n := range required {
		if !seen[n] {
			return fmt.Errorf("missing mandatory check: %s", n)
		}
	}
	return nil
}

// boundedOutput aborts checks that try to emit unbounded JSON on stdout.
// Stderr is intentionally not collected (it can contain access tokens).
type boundedOutput struct {
	data  bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.data.Len() {
		return 0, errors.New("GA probe stdout exceeds 4 MiB")
	}
	return b.data.Write(p)
}

func runProbe(ctx context.Context, c Check, p Plan, r Report, uuids []string) (SealedProbe, error) {
	result := SealedProbe{Name: c.Name}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	exe := exec.CommandContext(cctx, c.Command[0], c.Command[1:]...)
	exe.Dir = filepath.Dir(p.SourceArchive)
	// No backend credentials or signing keys are exposed to test subprocesses.
	env := []string{}
	for _, s := range os.Environ() {
		if strings.HasPrefix(s, "LAUNCHER_MIGRATION_GA_") || strings.HasPrefix(s, "LAUNCHER_ADMIN_TOKEN=") || strings.HasPrefix(s, "MIGRATION_GA_") {
			continue
		}
		env = append(env, s)
	}
	exe.Env = env
	stdout := &boundedOutput{limit: 4 << 20}
	exe.Stdout = stdout
	started := time.Now()
	e := exe.Run()
	out := stdout.data.Bytes()
	result.DurationMS = time.Since(started).Milliseconds()
	if cctx.Err() != nil {
		return result, fmt.Errorf("%s: %w", c.Name, cctx.Err())
	}
	if e != nil {
		return result, fmt.Errorf("%s: independent check failed: %w", c.Name, e)
	}
	var probe Probe
	if e = decodeStrict(out, &probe); e != nil {
		return result, fmt.Errorf("%s: malformed check output: %w", c.Name, e)
	}
	if !probe.Passed || probe.Name != c.Name || probe.RunID != p.RunID || probe.ReportSHA256 != r.ReportSHA256 || probe.SourceSHA256 != r.SourceSHA256 || probe.SourceVersion != p.SourceVersion || probe.TargetReleaseSHA256 != p.TargetReleaseSHA256 || !digest(probe.EvidenceSHA256) {
		return result, fmt.Errorf("%s: missing, false or unbound check evidence", c.Name)
	}
	if !filepath.IsAbs(probe.EvidenceFile) {
		return result, fmt.Errorf("%s: evidence path must be absolute", c.Name)
	}
	info, e := os.Stat(probe.EvidenceFile)
	if e != nil || info.ModTime().Before(started.Add(-2*time.Second)) || info.ModTime().After(time.Now().Add(time.Minute)) {
		return result, fmt.Errorf("%s: evidence not freshly generated by this check", c.Name)
	}
	actual, e := shaFile(probe.EvidenceFile, 128<<20)
	if e != nil || actual != probe.EvidenceSHA256 {
		return result, fmt.Errorf("%s: evidence file checksum invalid: %v", c.Name, e)
	}
	if c.Name == "uuid-world-plugin-data" {
		if len(probe.SourceUUIDs) != len(uuids) || len(probe.TargetUUIDs) != len(uuids) {
			return result, errors.New("UUID check lacks complete player population")
		}
		sort.Strings(probe.SourceUUIDs)
		sort.Strings(probe.TargetUUIDs)
		for i, id := range uuids {
			if id != probe.SourceUUIDs[i] || id != probe.TargetUUIDs[i] {
				return result, errors.New("UUID mapping disagrees with MIG13")
			}
		}
		if !digest(probe.SourceWorldSHA256) || probe.SourceWorldSHA256 != probe.TargetWorldSHA256 || !digest(probe.SourcePluginSHA256) || probe.SourcePluginSHA256 != probe.TargetPluginSHA256 {
			return result, errors.New("world or plugin data does not match")
		}
	}
	raw, _ := json.Marshal(probe)
	result.SHA256 = hash(raw)
	result.EvidenceSHA256 = actual
	return result, nil
}
func signingKey(filename string) (ed25519.PrivateKey, error) {
	info, e := os.Stat(filename)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("GA private key must be regular and owner-only (0600)")
	}
	b, e := os.ReadFile(filename)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected PEM PKCS#8 Ed25519 key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signer must be independent Ed25519 key")
	}
	return k, nil
}
func signBytes(b Bundle) ([]byte, error) { b.Signature = ""; return json.Marshal(b) }
func seal(b Bundle, key ed25519.PrivateKey) (Bundle, error) {
	b.PublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	raw, e := signBytes(b)
	if e != nil {
		return b, e
	}
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("Launcher-Migration-GA-0.34.0\x00"), raw...)))
	return b, nil
}
func verifyBundle(b Bundle, public ed25519.PublicKey) error {
	if b.Format != format || b.Version != version || !commitHash(b.CommitSHA) || !gravit57.MatchString(b.SourceVersion) || !digest(b.TrustedGravitJarSHA256) || !digest(b.TargetReleaseSHA256) || !digest(b.ReportSHA256) || !digest(b.SourceSHA256) || b.RunID == "" || b.ProjectID == "" || b.ReviewedBy == "" || !digest(b.ReviewEvidenceSHA256) || len(b.Checks) != len(required) {
		return errors.New("incomplete GA certificate")
	}
	key, e := base64.StdEncoding.DecodeString(b.PublicKey)
	if e != nil || !bytes.Equal(key, public) {
		return errors.New("certificate signer differs from trusted key")
	}
	signature, e := base64.StdEncoding.DecodeString(b.Signature)
	if e != nil {
		return e
	}
	raw, e := signBytes(b)
	if e != nil {
		return e
	}
	if !ed25519.Verify(public, append([]byte("Launcher-Migration-GA-0.34.0\x00"), raw...), signature) {
		return errors.New("invalid GA signature")
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if seen[c.Name] || !digest(c.SHA256) || !digest(c.EvidenceSHA256) {
			return errors.New("invalid/duplicate GA check")
		}
		seen[c.Name] = true
	}
	for _, n := range required {
		if !seen[n] {
			return fmt.Errorf("missing %s", n)
		}
	}
	t, e := time.Parse(time.RFC3339Nano, b.CompletedAt)
	if e != nil || t.After(time.Now().Add(time.Minute)) || time.Since(t) > 72*time.Hour {
		return errors.New("GA certificate is stale or future-dated")
	}
	return nil
}

// writePrivate publishes a fully fsynced file without ever replacing an
// existing GA result. Linking the temp file provides an atomic no-overwrite
// publish operation on the destination filesystem.
func writePrivate(path string, data []byte) error {
	if path == "" {
		return errors.New("output path is required")
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".migration-ga-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func certify(ctx context.Context, p Plan, token string, output string) error {
	if err := validatePlan(p); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("missing LAUNCHER_MIGRATION_GA_TOKEN")
	}
	source, e := shaFile(p.SourceArchive, 512<<20)
	if e != nil {
		return e
	}
	actualVersion, jarDigest, e := sourceJarEvidence(p.SourceArchive)
	if e != nil {
		return e
	}
	if actualVersion != p.SourceVersion || jarDigest != p.TrustedGravitJarSHA256 {
		return errors.New("source JAR disagrees with independently pinned Gravit binary/version")
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := strings.TrimRight(p.Backend, "/") + "/api/v1/admin/migration-runs/" + url.PathEscape(p.RunID) + "/report"
	var r Report
	if e = getJSON(ctx, client, endpoint, token, &r); e != nil {
		return e
	}
	if e = reportVerified(r); e != nil {
		return e
	}
	if r.RunID != p.RunID || r.ProjectID != p.ProjectID || r.SourceSHA256 != source {
		return errors.New("source ZIP, project or run does not match database report")
	}
	// Bind the tested Never release to an actually active cutover, not merely
	// a release ID or digest invented by the operator's test scripts.
	foundTarget := false
	for _, ev := range r.Evidence {
		if strings.HasPrefix(ev.Stage, "cutover_scope:") && ev.State == "verified" && ev.Details == "active" && ev.SHA256 == p.TargetReleaseSHA256 {
			foundTarget = true
		}
	}
	if !foundTarget {
		return errors.New("target digest is not an active verified Never release")
	}

	var review Review
	if e = getJSON(ctx, client, endpoint+"/review", token, &review); e != nil {
		return e
	}
	if review.Status != "rc_reviewed_not_ga_certified" || review.Report.ReportSHA256 != r.ReportSHA256 || review.ReviewedBy == "" || !digest(review.EvidenceSHA256) {
		return errors.New("missing matching immutable MIG13 RC review")
	}
	if err := reportVerified(review.Report); err != nil {
		return err
	}
	uuids := make([]string, 0, len(r.Identities))
	seen := map[string]bool{}
	for _, id := range r.Identities {
		if seen[id.UUID] {
			return errors.New("duplicate UUID in migration report")
		}
		seen[id.UUID] = true
		uuids = append(uuids, id.UUID)
	}
	sort.Strings(uuids)
	b := Bundle{Format: format, Version: version, RunID: p.RunID, ProjectID: p.ProjectID, CommitSHA: p.CommitSHA, SourceVersion: p.SourceVersion, TrustedGravitJarSHA256: p.TrustedGravitJarSHA256, TargetReleaseSHA256: p.TargetReleaseSHA256, ReportSHA256: r.ReportSHA256, SourceSHA256: source, ReviewedBy: review.ReviewedBy, ReviewEvidenceSHA256: review.EvidenceSHA256, Checks: []SealedProbe{}}
	for _, c := range p.Checks {
		check, e := runProbe(ctx, c, p, r, uuids)
		if e != nil {
			return e
		}
		b.Checks = append(b.Checks, check)
	}
	// A check must not change its own Gravit source bytes after the initial
	// source verification while still receiving a signed certificate.
	again, e := shaFile(p.SourceArchive, 512<<20)
	if e != nil {
		return e
	}
	if again != source {
		return errors.New("source archive changed during GA checks")
	}
	// Re-read the backend: a new source receipt, route or identity invalidates
	// a previously successful check before its certificate can be written.
	var after Report
	if e = getJSON(ctx, client, endpoint, token, &after); e != nil {
		return e
	}
	if e = reportVerified(after); e != nil {
		return e
	}
	if after.ReportSHA256 != r.ReportSHA256 {
		return errors.New("migration state changed during GA E2E; rerun")
	}
	// Access independent audit signing material only after all untrusted
	// probe commands have exited and the authoritative state was reread.
	key, e := signingKey(p.SigningKey)
	if e != nil {
		return e
	}
	b.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b, e = seal(b, key)
	if e != nil {
		return e
	}
	if e = verifyBundle(b, key.Public().(ed25519.PublicKey)); e != nil {
		return e
	}
	data, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	return writePrivate(output, append(data, '\n'))
}
func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Migration Center GA verification blocked:", err)
		os.Exit(1)
	}
}
func runMain(args []string) error {
	if len(args) == 0 {
		return errors.New("use certify --plan PLAN --output FILE or verify --certificate FILE --public-key PUB.pem")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	switch cmd {
	case "certify":
		p := fs.String("plan", "", "operator check plan JSON")
		out := fs.String("output", "", "signed certificate (created with 0600)")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		data, e := os.ReadFile(*p)
		if e != nil {
			return e
		}
		var plan Plan
		if e = decodeStrict(data, &plan); e != nil {
			return e
		}
		return certify(context.Background(), plan, os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"), *out)
	case "verify":
		file := fs.String("certificate", "", "signed evidence bundle")
		pub := fs.String("public-key", "", "trusted Ed25519 PUBLIC KEY PEM")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		data, e := os.ReadFile(*file)
		if e != nil {
			return e
		}
		var b Bundle
		if e = decodeStrict(data, &b); e != nil {
			return e
		}
		pemData, e := os.ReadFile(*pub)
		if e != nil {
			return e
		}
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("expected PEM public key")
		}
		anyKey, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return e
		}
		key, ok := anyKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("trusted key must be Ed25519")
		}
		if e = verifyBundle(b, key); e != nil {
			return e
		}
		fmt.Println("GA execution evidence signature and matrix verified:", b.RunID)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}
