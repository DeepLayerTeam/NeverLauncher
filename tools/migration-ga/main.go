// Исполнитель свидетельств Migration Center GA. Этот бинарник не объявляет развёртывание
// готовым к production лишь потому, что администратор рассмотрел отчёт миграции:
// он выполняет настроенные независимые проверки и заверяет их фактические результаты.
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

const version = "0.45.0"
const format = "launcher.gravit-ga-execution.v3"
const maxDocument = 32 << 20

var referenceClasses = []string{"fileauth-single", "sql-modded", "proxy-network"}

func referenceClassValid(s string) bool {
	for _, value := range referenceClasses {
		if s == value {
			return true
		}
	}
	return false
}

var gravit57 = regexp.MustCompile(`^5\.7\.[0-9]+$`)

// Эти проверки — исполняемые операторские пробы, а не заявления об универсальной поддержке загрузчиков.
// Референсный проект проверяет только реально используемые возможности;
// комбинированное покрытие включает FileAuth, SQL, официальную авторизацию, два загрузчика,
// необязательные файлы, текстуры, перенесённые исходные модули и безопасное переключение/возврат.
var commonChecks = []string{
	"uuid-world-plugin-data", "admin-permissions", "desktop-cache-install",
	"staged-cutover-canary", "operational-rollback-drill",
	"negative-cutover", "negative-rollback",
}
var classChecks = map[string][]string{
	"fileauth-single": {"fileauth-login", "skins", "negative-auth"},
	"sql-modded":      {"sql-login", "forge-launch-join", "neoforge-launch-join", "optional-presets", "skins", "negative-auth", "negative-optional"},
	"proxy-network":   {"official-login", "serverwrapper", "module-source-port", "negative-unknown-module", "negative-auth"},
}

func requiredForClass(class string) []string {
	if !referenceClassValid(class) {
		return nil
	}
	out := append([]string(nil), commonChecks...)
	return append(out, classChecks[class]...)
}

var required = func() []string { // объединение, используется только для ограничения проверяемых имён
	seen := map[string]bool{}
	var out []string
	for _, class := range referenceClasses {
		for _, name := range requiredForClass(class) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}()

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

// Это повторяет сетевую схему отчёта v1 Backend, включая канонический
// порядок полей структуры Go, чтобы квитанцию нельзя было привязать к изменённому отчёту.
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
	Name             string   `json:"name"`
	ExecutableSHA256 string   `json:"executableSha256"`
	Command          []string `json:"command"`
	TimeoutSeconds   int      `json:"timeoutSeconds"`
}
type Plan struct {
	ReferenceClass         string  `json:"referenceClass"`
	Backend                string  `json:"backend"`
	RunID                  string  `json:"runId"`
	ProjectID              string  `json:"projectId"`
	SourceArchive          string  `json:"sourceArchive"`
	SnapshotSourceDir      string  `json:"snapshotSourceDir"`
	SnapshotTargetDir      string  `json:"snapshotTargetDir"`
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
	Name             string `json:"name"`
	ExecutableSHA256 string `json:"executableSha256"`
	SHA256           string `json:"sha256"`
	EvidenceSHA256   string `json:"evidenceSha256"`
	DurationMS       int64  `json:"durationMs"`
}
type Bundle struct {
	ReferenceClass         string        `json:"referenceClass"`
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
		return errors.New("Несоответствие: отчёт о миграции контрольная сумма")
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
	// Все ответы Launcher Admin упакованы в оболочку {"data": ...}.
	// Не принимать прямой или неизвестный ответ, который случайно соответствует
	// лишь части ожидаемых полей отчёта.
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

// sourceJarVersion проверяет реальный бинарник LaunchServer внутри MIG03,
// а не заявленную оператором версию. Намеренно принимаются только манифесты
// с явной идентичностью продукта Gravit/LaunchServer.
func sourceJarEvidence(archivePath string) (string, string, error) {
	outer, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", "", err
	}
	defer outer.Close()
	if len(outer.File) > 30000 {
		return "", "", errors.New("Превышено число элементов исходного ZIP")
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
			return "", "", errors.New("Небезопасный объект: LaunchServer JAR размер")
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
				return "", "", errors.New("Некорректное значение: JAR манифест")
			}
			manifest = string(b)
		}
		if manifest == "" {
			return "", "", errors.New("Отсутствует: LaunchServer JAR манифест")
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
			return "", "", errors.New("Не поддерживается: JAR версия")
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
	if !referenceClassValid(p.ReferenceClass) || len(p.RunID) < 8 || len(p.RunID) > 128 || p.ProjectID == "" || !commitHash(p.CommitSHA) || !gravit57.MatchString(p.SourceVersion) || patch < 0 || patch > 12 || !digest(p.TrustedGravitJarSHA256) || !digest(p.TargetReleaseSHA256) || p.SigningKey == "" || p.SourceArchive == "" {
		return errors.New("missing/invalid run, project, source, signing key or commit SHA-256")
	}
	if !filepath.IsAbs(p.SourceArchive) || !filepath.IsAbs(p.SigningKey) || !filepath.IsAbs(p.SnapshotSourceDir) || !filepath.IsAbs(p.SnapshotTargetDir) || filepath.Clean(p.SnapshotSourceDir) == filepath.Clean(p.SnapshotTargetDir) {
		return errors.New("source archive and signer key paths must be absolute")
	}
	if githubSHA := os.Getenv("GITHUB_SHA"); githubSHA != "" && githubSHA != p.CommitSHA {
		return errors.New("plan commit differs from checked-out CI commit")
	}
	if len(p.Checks) != len(requiredForClass(p.ReferenceClass)) {
		return fmt.Errorf("exactly %d independently executed GA checks are required for %s", len(requiredForClass(p.ReferenceClass)), p.ReferenceClass)
	}
	seen := map[string]bool{}
	for _, c := range p.Checks {
		if seen[c.Name] || len(c.Command) == 0 || !filepath.IsAbs(c.Command[0]) || !digest(c.ExecutableSHA256) || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 900 {
			return errors.New("duplicate/invalid check command")
		}
		seen[c.Name] = true
	}
	for _, n := range requiredForClass(p.ReferenceClass) {
		if !seen[n] {
			return fmt.Errorf("missing mandatory check: %s", n)
		}
	}
	return nil
}

// boundedOutput прерывает проверки, пытающиеся вывести неограниченный JSON в stdout.
// Stderr намеренно не собирается (может содержать токены доступа).
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

func runProbe(ctx context.Context, c Check, p Plan, r Report, uuids []string, evidenceDir string) (SealedProbe, error) {
	result := SealedProbe{Name: c.Name, ExecutableSHA256: c.ExecutableSHA256}
	if err := verifyExecutable(c); err != nil {
		return result, fmt.Errorf("%s check executable: %w", c.Name, err)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	exe := exec.CommandContext(cctx, c.Command[0], c.Command[1:]...)
	exe.Dir = filepath.Dir(p.SourceArchive)
	// Тестовым подпроцессам не предоставляются учётные данные Backend или ключи подписи.
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
	// Stderr проверки может содержать учётные данные; не допускать его в журналы CI.
	exe.Stderr = io.Discard
	started := time.Now()
	e := exe.Run()
	out := stdout.data.Bytes()
	// Подменённый исполняемый файл теста не может участвовать в подписанном результате GA.
	if err := verifyExecutable(c); err != nil {
		return result, fmt.Errorf("%s check executable changed: %w", c.Name, err)
	}
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
		native, nativeErr := auditState(p.SnapshotSourceDir, p.SnapshotTargetDir)
		if nativeErr != nil || !native.Matched || native.SourceWorldSHA256 != probe.SourceWorldSHA256 || native.SourcePluginSHA256 != probe.SourcePluginSHA256 || len(native.SourceUUIDs) != len(uuids) {
			return result, errors.New("independent native source/target snapshot comparison failed")
		}
		for i, id := range uuids {
			if id != native.SourceUUIDs[i] {
				return result, errors.New("native snapshot UUIDs disagree with migrated identities")
			}
		}
		auditRaw, readErr := os.ReadFile(probe.EvidenceFile)
		if readErr != nil || len(auditRaw) > maxDocument || validateStateAuditEvidence(auditRaw, probe) != nil {
			return result, errors.New("native state audit evidence missing, inconsistent or unreadable")
		}
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
	raw, e := json.Marshal(probe)
	if e != nil {
		return result, e
	}
	if e = preserveEvidence(evidenceDir, c.Name, probe.EvidenceFile, actual, raw); e != nil {
		return result, fmt.Errorf("%s: preserving independent evidence: %w", c.Name, e)
	}
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
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("Launcher-Migration-GA-0.45.0\x00"), raw...)))
	return b, nil
}
func verifyBundle(b Bundle, public ed25519.PublicKey) error {
	if b.Format != format || b.Version != version || !referenceClassValid(b.ReferenceClass) || !commitHash(b.CommitSHA) || !gravit57.MatchString(b.SourceVersion) || !digest(b.TrustedGravitJarSHA256) || !digest(b.TargetReleaseSHA256) || !digest(b.ReportSHA256) || !digest(b.SourceSHA256) || b.RunID == "" || b.ProjectID == "" || b.ReviewedBy == "" || !digest(b.ReviewEvidenceSHA256) || len(b.Checks) != len(requiredForClass(b.ReferenceClass)) {
		return errors.New("Неполные данные: GA сертификат")
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
	if !ed25519.Verify(public, append([]byte("Launcher-Migration-GA-0.45.0\x00"), raw...), signature) {
		return errors.New("Некорректное значение: GA подпись")
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if seen[c.Name] || !digest(c.SHA256) || !digest(c.EvidenceSHA256) || !digest(c.ExecutableSHA256) {
			return errors.New("invalid/duplicate GA check")
		}
		seen[c.Name] = true
	}
	for _, n := range requiredForClass(b.ReferenceClass) {
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

// writePrivate публикует полностью fsync-синхронизированный файл, никогда не заменяя
// существующий результат GA. Связывание временного файла жёсткой ссылкой обеспечивает атомарную публикацию
// без перезаписи в целевой файловой системе.
func writePrivate(path string, data []byte) error {
	if path == "" {
		return errors.New("Необходимо указать путь вывода")
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

func certify(ctx context.Context, p Plan, token string, output, evidenceDir string) error {
	if err := validatePlan(p); err != nil {
		return err
	}
	if evidenceDir == "" || !filepath.IsAbs(evidenceDir) || evidenceDir == filepath.Dir(output) {
		return errors.New("a separate absolute evidence directory is required")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("Отсутствует: LAUNCHER_MIGRATION_GA_TOKEN")
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
	// Связать протестированный выпуск с действительно активным переключением, а не просто
	// ID выпуска или дайджестом, выдуманным скриптами тестирования оператора.
	foundTarget := false
	for _, ev := range r.Evidence {
		if strings.HasPrefix(ev.Stage, "cutover_scope:") && ev.State == "verified" && ev.Details == "active" && ev.SHA256 == p.TargetReleaseSHA256 {
			foundTarget = true
		}
	}
	if !foundTarget {
		return errors.New("target digest is not an active verified release")
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
	b := Bundle{Format: format, Version: version, ReferenceClass: p.ReferenceClass, RunID: p.RunID, ProjectID: p.ProjectID, CommitSHA: p.CommitSHA, SourceVersion: p.SourceVersion, TrustedGravitJarSHA256: p.TrustedGravitJarSHA256, TargetReleaseSHA256: p.TargetReleaseSHA256, ReportSHA256: r.ReportSHA256, SourceSHA256: source, ReviewedBy: review.ReviewedBy, ReviewEvidenceSHA256: review.EvidenceSHA256, Checks: []SealedProbe{}}
	// Создавать каталог свидетельств только после проверки авторитетного отчёта и
	// неизменяемого рассмотрения оператором. Ранее созданные каталоги не используются повторно.
	if e = os.Mkdir(evidenceDir, 0700); e != nil {
		return fmt.Errorf("new evidence directory: %w", e)
	}
	for _, c := range p.Checks {
		check, e := runProbe(ctx, c, p, r, uuids, evidenceDir)
		if e != nil {
			return e
		}
		b.Checks = append(b.Checks, check)
	}
	if err := ensureSnapshotStillMatches(p, evidenceDir); err != nil {
		return fmt.Errorf("snapshots changed during GA execution: %w", err)
	}
	// Проверка не должна менять собственные исходные байты Gravit после первоначальной
	// проверки источника и всё же получать подписанный сертификат.
	again, e := shaFile(p.SourceArchive, 512<<20)
	if e != nil {
		return e
	}
	if again != source {
		return errors.New("source archive changed during GA checks")
	}
	// Повторно прочитать Backend: новая квитанция источника, маршрут или идентичность делают
	// предыдущую успешную проверку недействительной до записи сертификата.
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
	var afterReview Review
	if e = getJSON(ctx, client, endpoint+"/review", token, &afterReview); e != nil {
		return e
	}
	if afterReview.Status != review.Status || afterReview.ReviewedBy != review.ReviewedBy || afterReview.ReviewedAt != review.ReviewedAt || afterReview.EvidenceReference != review.EvidenceReference || afterReview.EvidenceSHA256 != review.EvidenceSHA256 || afterReview.Report.ReportSHA256 != r.ReportSHA256 {
		return errors.New("migration operator review changed during GA E2E; rerun")
	}
	// Доступ к материалам подписи независимого аудита допускается только после завершения всех недоверенных
	// команд проб и повторного чтения авторитетного состояния.
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
		return errors.New("use certify, verify, verify-cohort, or integration-audit --backend URL --project ID --run ID --extension ID --output FILE")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	switch cmd {
	case "integration-audit":
		return integrationAuditCommand0491(args[1:])
	case "manual-actions":
		planFile := fs.String("plan", "", "План миграции для оператора")
		out := fs.String("output", "", "Новый Markdown-файл списка задач оператора")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		raw, e := os.ReadFile(*planFile)
		if e != nil {
			return e
		}
		var p Plan
		if e = decodeStrict(raw, &p); e != nil {
			return e
		}
		return exportManualWorklist(context.Background(), p, os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"), *out)
	case "audit-state":
		source := fs.String("source", "", "Абсолютный путь к каталогу исходного снимка")
		target := fs.String("target", "", "Абсолютный путь к каталогу целевого снимка")
		out := fs.String("output", "", "Новый приватный JSON-файл аудиторских свидетельств")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return executeStateAudit(*source, *target, *out)
	case "certify":
		evidenceDir := fs.String("evidence-dir", "", "Новый приватный каталог для полного набора свидетельств проверки")
		p := fs.String("plan", "", "JSON-план проверок оператора")
		out := fs.String("output", "", "Подписанный сертификат (создаётся с правами 0600)")
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
		return certify(context.Background(), plan, os.Getenv("LAUNCHER_MIGRATION_GA_TOKEN"), *out, *evidenceDir)
	case "verify":
		evidenceDir := fs.String("evidence-dir", "", "Сохранённый каталог свидетельств (обязательно)")
		file := fs.String("certificate", "", "Подписанный пакет свидетельств")
		pub := fs.String("public-key", "", "Доверенный ПУБЛИЧНЫЙ ключ Ed25519 в PEM")
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
			return errors.New("Требуемый формат для доверенный ключ: Ed25519")
		}
		if e = verifyBundle(b, key); e != nil {
			return e
		}
		if e = verifyEvidence(b, *evidenceDir); e != nil {
			return e
		}
		fmt.Println("GA evidence signature, matrix and stored artifacts verified:", b.RunID)
		return nil
	case "verify-cohort", "verify-cohort-live":
		key := fs.String("public-key", "", "Доверенный публичный ключ Ed25519")
		single := fs.String("fileauth-single", "", "Сертификат fileauth")
		singleDir := fs.String("fileauth-single-evidence", "", "Каталог свидетельств fileauth")
		modded := fs.String("sql-modded", "", "Сертификат SQL/modded")
		moddedDir := fs.String("sql-modded-evidence", "", "Каталог свидетельств SQL/modded")
		network := fs.String("proxy-network", "", "Сетевой сертификат")
		networkDir := fs.String("proxy-network-evidence", "", "Каталог сетевых свидетельств")
		singlePlan := fs.String("fileauth-single-plan", "", "План проверки работающего источника fileauth")
		moddedPlan := fs.String("sql-modded-plan", "", "План проверки работающего источника SQL/modded")
		networkPlan := fs.String("proxy-network-plan", "", "План проверки работающего сетевого источника")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		cohort := map[string]CohortInput{
			"fileauth-single": {Certificate: *single, EvidenceDir: *singleDir},
			"sql-modded":      {Certificate: *modded, EvidenceDir: *moddedDir},
			"proxy-network":   {Certificate: *network, EvidenceDir: *networkDir},
		}
		if cmd == "verify-cohort-live" {
			return verifyCohortLiveCommand(context.Background(), *key, cohort, loadCohortPlanPaths(*singlePlan, *moddedPlan, *networkPlan))
		}
		return verifyCohort(*key, cohort)
	default:
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}
