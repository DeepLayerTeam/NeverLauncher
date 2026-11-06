// Средство сбора свидетельств для Migration Center GA. Эта программа не считает
// развёртывание готовым к эксплуатации лишь после изучения отчёта администратором:
// она выполняет независимые проверки и подписывает их фактические результаты.
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

// Это исполняемые операторские проверки, а не заявление об универсальной
// поддержке загрузчиков. Эталонный проект проверяет только используемые функции;
// общий охват включает FileAuth, SQL, официальную авторизацию, два загрузчика,
// дополнительные файлы, текстуры, модули исходного порта и безопасное переключение/откат.
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

var required = func() []string { // union, used only to bound check names
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

// Повторяется сетевой формат отчёта Backend v1, включая канонический порядок
// полей структуры Go: свидетельство нельзя перепривязать к изменённому отчёту.
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
		return errors.New("Пустой или слишком большой документ JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if e := d.Decode(&extra); !errors.Is(e, io.EOF) {
		return errors.New("После JSON-документа обнаружены дополнительные данные")
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
		return "", errors.New("Подтверждающие данные должны храниться в непустом обычном файле допустимого размера")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil {
		return "", e
	}
	if n != st.Size() {
		return "", errors.New("Доказательные данные изменились во время чтения")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func reportVerified(r Report) error {
	if r.Format != "launcher.gravit-migration-report.v1" || r.Status != "review_required" || len(r.Blockers) != 0 || !digest(r.SourceSHA256) || !digest(r.InventorySHA256) || !digest(r.ReportSHA256) || len(r.Identities) == 0 {
		return errors.New("Отчёт о миграции заблокирован или не завершён")
	}
	d := r.ReportSHA256
	r.ReportSHA256 = ""
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if hash(b) != d {
		return errors.New("Несовпадение: контрольная сумма отчёта миграции")
	}
	stages := map[string]string{}
	for _, ev := range r.Evidence {
		if _, ok := stages[ev.Stage]; ok {
			return errors.New("Обнаружен дубликат: этап отчёта")
		}
		stages[ev.Stage] = ev.State
	}
	for _, n := range []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"} {
		if stages[n] != "verified" {
			return fmt.Errorf("Этап миграции %s не прошёл проверку", n)
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
		return errors.New("Отсутствует: активная проверенная область переключения миграции")
	}
	for _, id := range r.Identities {
		if id.Status != "imported" && id.Status != "matched" || id.TargetUserID == "" {
			return errors.New("Перенесённая учётная запись не сопоставлена")
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
		return fmt.Errorf("Backend миграции вернул HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxDocument+1))
	if e != nil {
		return e
	}
	// Все ответы Launcher Admin имеют оболочку {"data": ...}.
	// Не принимайте ответ без оболочки или неизвестного формата, даже если
	// часть полей совпадает с ожидаемым отчётом.
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
		return errors.New("Адрес Backend должен содержать только схему, хост и порт")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return errors.New("Требуется HTTPS, кроме обращения к числовому адресу loopback")
	}
	return nil
}

// sourceJarVersion проверяет реальный бинарный файл LaunchServer из MIG03,
// а не заявленную оператором версию. Принимаются только манифесты с явно
// указанной идентичностью продукта Gravit/LaunchServer.
func sourceJarEvidence(archivePath string) (string, string, error) {
	outer, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", "", err
	}
	defer outer.Close()
	if len(outer.File) > 30000 {
		return "", "", errors.New("Слишком много файлов в исходном ZIP")
	}
	found := ""
	jarHash := ""
	for _, f := range outer.File {
		if !strings.EqualFold(path.Base(f.Name), "LaunchServer.jar") {
			continue
		}
		if found != "" {
			return "", "", errors.New("Обнаружено несколько JAR-файлов LaunchServer")
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > 32<<20 || f.CompressedSize64 == 0 {
			return "", "", errors.New("Небезопасное значение: размер JAR LaunchServer")
		}
		reader, e := f.Open()
		if e != nil {
			return "", "", e
		}
		data, e := io.ReadAll(io.LimitReader(reader, (32<<20)+1))
		reader.Close()
		if e != nil || uint64(len(data)) != f.UncompressedSize64 {
			return "", "", errors.New("Не удалось прочитать JAR-файл LaunchServer")
		}
		nested, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return "", "", e
		}
		if len(nested.File) > 20000 {
			return "", "", errors.New("Слишком много элементов в JAR-архиве")
		}
		var manifest string
		for _, item := range nested.File {
			if !strings.EqualFold(item.Name, "META-INF/MANIFEST.MF") {
				continue
			}
			if manifest != "" || item.UncompressedSize64 > 64<<10 {
				return "", "", errors.New("Повторяющийся или слишком большой манифест JAR")
			}
			read, e := item.Open()
			if e != nil {
				return "", "", e
			}
			b, e := io.ReadAll(io.LimitReader(read, (64<<10)+1))
			read.Close()
			if e != nil || uint64(len(b)) != item.UncompressedSize64 {
				return "", "", errors.New("Некорректное значение: манифест JAR")
			}
			manifest = string(b)
		}
		if manifest == "" {
			return "", "", errors.New("Отсутствует манифест JAR LaunchServer")
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
			return "", "", errors.New("Невозможно подтвердить, что JAR принадлежит Gravit LaunchServer")
		}
		jarHash = hash(data)
		ver = strings.TrimPrefix(ver, "v")
		if !gravit57.MatchString(ver) {
			return "", "", errors.New("Не поддерживается: версия JAR")
		}
		found = ver
	}
	if found == "" {
		return "", "", errors.New("JAR-файл LaunchServer отсутствует")
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
		return errors.New("Отсутствуют или некорректны идентификаторы запуска, проекта, источника, ключа подписи либо SHA-256 коммита")
	}
	if !filepath.IsAbs(p.SourceArchive) || !filepath.IsAbs(p.SigningKey) || !filepath.IsAbs(p.SnapshotSourceDir) || !filepath.IsAbs(p.SnapshotTargetDir) || filepath.Clean(p.SnapshotSourceDir) == filepath.Clean(p.SnapshotTargetDir) {
		return errors.New("Пути исходного архива и ключа подписи должны быть абсолютными")
	}
	if githubSHA := os.Getenv("GITHUB_SHA"); githubSHA != "" && githubSHA != p.CommitSHA {
		return errors.New("Коммит плана отличается от коммита, извлечённого в CI")
	}
	if len(p.Checks) != len(requiredForClass(p.ReferenceClass)) {
		return fmt.Errorf("Требуется ровно %d независимо выполненных проверок GA для %s", len(requiredForClass(p.ReferenceClass)), p.ReferenceClass)
	}
	seen := map[string]bool{}
	for _, c := range p.Checks {
		if seen[c.Name] || len(c.Command) == 0 || !filepath.IsAbs(c.Command[0]) || !digest(c.ExecutableSHA256) || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 900 {
			return errors.New("Повторяющаяся или некорректная команда проверки")
		}
		seen[c.Name] = true
	}
	for _, n := range requiredForClass(p.ReferenceClass) {
		if !seen[n] {
			return fmt.Errorf("Отсутствует: обязательная проверка: %s", n)
		}
	}
	return nil
}

// boundedOutput прерывает проверки с неограниченным выводом JSON в stdout.
// Stderr намеренно не собирается: он может содержать токены доступа.
type boundedOutput struct {
	data  bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.data.Len() {
		return 0, errors.New("Вывод проверки GA превышает 4 МиБ")
	}
	return b.data.Write(p)
}

func runProbe(ctx context.Context, c Check, p Plan, r Report, uuids []string, evidenceDir string) (SealedProbe, error) {
	result := SealedProbe{Name: c.Name, ExecutableSHA256: c.ExecutableSHA256}
	if err := verifyExecutable(c); err != nil {
		return result, fmt.Errorf("Не удалось проверить исполняемый файл %s: %w", c.Name, err)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	exe := exec.CommandContext(cctx, c.Command[0], c.Command[1:]...)
	exe.Dir = filepath.Dir(p.SourceArchive)
	// Учётные данные Backend и ключи подписи не передаются тестовым подпроцессам.
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
	// Stderr проверки может содержать учётные данные: не записывайте его в журналы CI.
	exe.Stderr = io.Discard
	started := time.Now()
	e := exe.Run()
	out := stdout.data.Bytes()
	// Подменённая тестовая программа не может участвовать в подписанном результате GA.
	if err := verifyExecutable(c); err != nil {
		return result, fmt.Errorf("Исполняемый файл проверки %s был изменён: %w", c.Name, err)
	}
	result.DurationMS = time.Since(started).Milliseconds()
	if cctx.Err() != nil {
		return result, fmt.Errorf("%s: %w", c.Name, cctx.Err())
	}
	if e != nil {
		return result, fmt.Errorf("Ошибка независимой проверки %s: %w", c.Name, e)
	}
	var probe Probe
	if e = decodeStrict(out, &probe); e != nil {
		return result, fmt.Errorf("%s: некорректный вывод проверки: %w", c.Name, e)
	}
	if !probe.Passed || probe.Name != c.Name || probe.RunID != p.RunID || probe.ReportSHA256 != r.ReportSHA256 || probe.SourceSHA256 != r.SourceSHA256 || probe.SourceVersion != p.SourceVersion || probe.TargetReleaseSHA256 != p.TargetReleaseSHA256 || !digest(probe.EvidenceSHA256) {
		return result, fmt.Errorf("%s: данные проверки отсутствуют, отрицательны или не имеют привязки", c.Name)
	}
	if !filepath.IsAbs(probe.EvidenceFile) {
		return result, fmt.Errorf("%s: путь к подтверждающим данным должен быть абсолютным", c.Name)
	}
	info, e := os.Stat(probe.EvidenceFile)
	if e != nil || info.ModTime().Before(started.Add(-2*time.Second)) || info.ModTime().After(time.Now().Add(time.Minute)) {
		return result, fmt.Errorf("%s: данные проверки не были созданы заново этой проверкой", c.Name)
	}
	actual, e := shaFile(probe.EvidenceFile, 128<<20)
	if e != nil || actual != probe.EvidenceSHA256 {
		return result, fmt.Errorf("Некорректная контрольная сумма файла подтверждения %s: %v", c.Name, e)
	}
	if c.Name == "uuid-world-plugin-data" {
		native, nativeErr := auditState(p.SnapshotSourceDir, p.SnapshotTargetDir)
		if nativeErr != nil || !native.Matched || native.SourceWorldSHA256 != probe.SourceWorldSHA256 || native.SourcePluginSHA256 != probe.SourcePluginSHA256 || len(native.SourceUUIDs) != len(uuids) {
			return result, errors.New("Ошибка независимого сравнения нативных снимков источника и назначения")
		}
		for i, id := range uuids {
			if id != native.SourceUUIDs[i] {
				return result, errors.New("UUID в нативном снимке не совпадают с перенесёнными идентификаторами")
			}
		}
		auditRaw, readErr := os.ReadFile(probe.EvidenceFile)
		if readErr != nil || len(auditRaw) > maxDocument || validateStateAuditEvidence(auditRaw, probe) != nil {
			return result, errors.New("Данные проверки нативного состояния отсутствуют, противоречивы или недоступны для чтения")
		}
		if len(probe.SourceUUIDs) != len(uuids) || len(probe.TargetUUIDs) != len(uuids) {
			return result, errors.New("Проверка UUID не охватывает всех игроков")
		}
		sort.Strings(probe.SourceUUIDs)
		sort.Strings(probe.TargetUUIDs)
		for i, id := range uuids {
			if id != probe.SourceUUIDs[i] || id != probe.TargetUUIDs[i] {
				return result, errors.New("Сопоставление UUID не совпадает с MIG13")
			}
		}
		if !digest(probe.SourceWorldSHA256) || probe.SourceWorldSHA256 != probe.TargetWorldSHA256 || !digest(probe.SourcePluginSHA256) || probe.SourcePluginSHA256 != probe.TargetPluginSHA256 {
			return result, errors.New("Данные мира или плагинов не совпадают")
		}
	}
	raw, e := json.Marshal(probe)
	if e != nil {
		return result, e
	}
	if e = preserveEvidence(evidenceDir, c.Name, probe.EvidenceFile, actual, raw); e != nil {
		return result, fmt.Errorf("%s: ошибка сохранения независимых доказательных данных: %w", c.Name, e)
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
		return nil, errors.New("Закрытый ключ GA должен быть обычным файлом с правами владельца 0600")
	}
	b, e := os.ReadFile(filename)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("Ожидался ключ Ed25519 в формате PEM PKCS#8")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Для подписант требуется: независимый ключ Ed25519")
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
		return errors.New("Неполный сертификат GA")
	}
	key, e := base64.StdEncoding.DecodeString(b.PublicKey)
	if e != nil || !bytes.Equal(key, public) {
		return errors.New("Ключ подписанта сертификата отличается от доверенного ключа")
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
		return errors.New("Некорректное значение: подпись GA")
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if seen[c.Name] || !digest(c.SHA256) || !digest(c.EvidenceSHA256) || !digest(c.ExecutableSHA256) {
			return errors.New("Некорректная или повторяющаяся проверка GA")
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
		return errors.New("Сертификат GA устарел или датирован будущим временем")
	}
	return nil
}

// writePrivate публикует полностью синхронизированный файл, не заменяя
// существующий результат GA. Жёсткая ссылка на временный файл обеспечивает
// атомарную публикацию без перезаписи в целевой файловой системе.
func writePrivate(path string, data []byte) error {
	if path == "" {
		return errors.New("Требуется: путь вывода")
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
		return errors.New("Требуется отдельный абсолютный путь к каталогу подтверждающих данных")
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
		return errors.New("Исходный JAR не совпадает с независимо закреплённым бинарным файлом или версией Gravit")
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
		return errors.New("ZIP источника, проект или запуск не совпадает с отчёт базы данных")
	}
	// Привязывайте проверяемый релиз к действительно активному переключению,
	// а не только к ID релиза или хешу, придуманному тестовыми скриптами оператора.
	foundTarget := false
	for _, ev := range r.Evidence {
		if strings.HasPrefix(ev.Stage, "cutover_scope:") && ev.State == "verified" && ev.Details == "active" && ev.SHA256 == p.TargetReleaseSHA256 {
			foundTarget = true
		}
	}
	if !foundTarget {
		return errors.New("Хеш целевого релиза не относится к активному проверенному выпуску")
	}

	var review Review
	if e = getJSON(ctx, client, endpoint+"/review", token, &review); e != nil {
		return e
	}
	if review.Status != "rc_reviewed_not_ga_certified" || review.Report.ReportSHA256 != r.ReportSHA256 || review.ReviewedBy == "" || !digest(review.EvidenceSHA256) {
		return errors.New("Отсутствует соответствующее неизменяемое заключение MIG13 RC")
	}
	if err := reportVerified(review.Report); err != nil {
		return err
	}
	uuids := make([]string, 0, len(r.Identities))
	seen := map[string]bool{}
	for _, id := range r.Identities {
		if seen[id.UUID] {
			return errors.New("Обнаружен дубликат: UUID в отчёте миграции")
		}
		seen[id.UUID] = true
		uuids = append(uuids, id.UUID)
	}
	sort.Strings(uuids)
	b := Bundle{Format: format, Version: version, ReferenceClass: p.ReferenceClass, RunID: p.RunID, ProjectID: p.ProjectID, CommitSHA: p.CommitSHA, SourceVersion: p.SourceVersion, TrustedGravitJarSHA256: p.TrustedGravitJarSHA256, TargetReleaseSHA256: p.TargetReleaseSHA256, ReportSHA256: r.ReportSHA256, SourceSHA256: source, ReviewedBy: review.ReviewedBy, ReviewEvidenceSHA256: review.EvidenceSHA256, Checks: []SealedProbe{}}
	// Создавайте каталог свидетельств только после проверки достоверного отчёта и
	// неизменяемого заключения оператора. Ранее созданные каталоги не используйте повторно.
	if e = os.Mkdir(evidenceDir, 0700); e != nil {
		return fmt.Errorf("Создание каталога доказательств: %w", e)
	}
	for _, c := range p.Checks {
		check, e := runProbe(ctx, c, p, r, uuids, evidenceDir)
		if e != nil {
			return e
		}
		b.Checks = append(b.Checks, check)
	}
	if err := ensureSnapshotStillMatches(p, evidenceDir); err != nil {
		return fmt.Errorf("Снимки изменились во время проверки GA: %w", err)
	}
	// Проверка не должна изменять исходные байты Gravit после первоначальной
	// проверки источника и при этом получать подписанный сертификат.
	again, e := shaFile(p.SourceArchive, 512<<20)
	if e != nil {
		return e
	}
	if again != source {
		return errors.New("Исходный архив изменился во время проверок GA")
	}
	// Повторно прочитайте состояние Backend: новая квитанция источника, маршрут или
	// идентичность аннулируют ранее успешную проверку до записи её сертификата.
	var after Report
	if e = getJSON(ctx, client, endpoint, token, &after); e != nil {
		return e
	}
	if e = reportVerified(after); e != nil {
		return e
	}
	if after.ReportSHA256 != r.ReportSHA256 {
		return errors.New("Состояние миграции изменилось во время сквозной проверки GA; выполните её повторно")
	}
	var afterReview Review
	if e = getJSON(ctx, client, endpoint+"/review", token, &afterReview); e != nil {
		return e
	}
	if afterReview.Status != review.Status || afterReview.ReviewedBy != review.ReviewedBy || afterReview.ReviewedAt != review.ReviewedAt || afterReview.EvidenceReference != review.EvidenceReference || afterReview.EvidenceSHA256 != review.EvidenceSHA256 || afterReview.Report.ReportSHA256 != r.ReportSHA256 {
		return errors.New("Заключение оператора изменилось во время сквозной проверки GA; повторите проверку")
	}
	// Обращайтесь к независимому ключевому материалу подписи аудита лишь после
	// завершения всех недоверенных команд проверки и повторного чтения достоверного состояния.
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
		fmt.Fprintln(os.Stderr, "Проверка GA центра миграции заблокирована:", err)
		os.Exit(1)
	}
}
func runMain(args []string) error {
	if len(args) == 0 {
		return errors.New("Используйте certify, verify, verify-cohort или integration-audit --backend URL --project ID --run ID --extension ID --output FILE")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	switch cmd {
	case "integration-audit":
		return integrationAuditCommand0491(args[1:])
	case "manual-actions":
		planFile := fs.String("plan", "", "План действий оператора миграции")
		out := fs.String("output", "", "Новый файл Markdown со списком ручных действий оператора")
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
		source := fs.String("source", "", "Абсолютный путь к каталогу снимка исходной системы")
		target := fs.String("target", "", "Абсолютный путь к каталогу снимка целевой системы")
		out := fs.String("output", "", "Новый закрытый JSON-файл свидетельств аудита")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return executeStateAudit(*source, *target, *out)
	case "certify":
		evidenceDir := fs.String("evidence-dir", "", "Новый закрытый каталог для всех свидетельств проверки")
		p := fs.String("plan", "", "JSON-файл плана проверок оператора")
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
		evidenceDir := fs.String("evidence-dir", "", "Сохранённый каталог доказательств (обязательно)")
		file := fs.String("certificate", "", "Подписанный комплект свидетельств")
		pub := fs.String("public-key", "", "Доверенный открытый ключ Ed25519 в формате PEM")
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
			return errors.New("Ожидался открытый ключ в формате PEM")
		}
		anyKey, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return e
		}
		key, ok := anyKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("Доверенный ключ: требуется Ed25519")
		}
		if e = verifyBundle(b, key); e != nil {
			return e
		}
		if e = verifyEvidence(b, *evidenceDir); e != nil {
			return e
		}
		fmt.Println("Подпись доказательств GA, матрица и сохранённые артефакты проверены:", b.RunID)
		return nil
	case "verify-cohort", "verify-cohort-live":
		key := fs.String("public-key", "", "Доверенный открытый ключ Ed25519")
		single := fs.String("fileauth-single", "", "Сертификат FileAuth")
		singleDir := fs.String("fileauth-single-evidence", "", "Каталог свидетельств FileAuth")
		modded := fs.String("sql-modded", "", "Сертификат SQL/модифицированного клиента")
		moddedDir := fs.String("sql-modded-evidence", "", "Каталог доказательств SQL/модифицированного клиента")
		network := fs.String("proxy-network", "", "Сертификат сетевой проверки")
		networkDir := fs.String("proxy-network-evidence", "", "Каталог свидетельств сетевой проверки")
		singlePlan := fs.String("fileauth-single-plan", "", "План проверки действующего источника FileAuth")
		moddedPlan := fs.String("sql-modded-plan", "", "План действующего источника SQL/модифицированного клиента")
		networkPlan := fs.String("proxy-network-plan", "", "План проверки действующего сетевого источника")
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
		return fmt.Errorf("Неизвестное значение: подкоманда %q", cmd)
	}
}
