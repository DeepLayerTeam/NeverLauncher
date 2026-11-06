package main

// Независимый точный по байтам допуск GA на финальной границе подписания выпуска. Он
// намеренно проверяется самим CLI, а не только shell-процессом. Для исторической 0.36.0
// остаются прежний домен утверждения и процедура упаковки.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const gaTargetsDomain0361 = "launcher.ga.targets.v2\x00"

var gaTargetNames0361 = []string{"windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"}
var gaCheckNames0361 = []string{"nativeInstall", "desktopLaunch", "minecraftLaunch", "serverJoin", "releaseRollback", "security", "performance", "operations", "osSignature"}
var gaHex0361 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var gaCommit0361 = regexp.MustCompile(`^[a-f0-9]{40}$`)
var gaExecutionID0361 = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,128}$`)

type gaFileHash0361 struct {
	SHA string `json:"sha256"`
}
type gaTarget0361 struct {
	Target     string                    `json:"target"`
	Status     string                    `json:"status"`
	BinarySHA  string                    `json:"binarySha256"`
	PackageSHA string                    `json:"packageSha256"`
	Checks     map[string]gaFileHash0361 `json:"checks"`
}
type gaApproval0361 struct {
	Schema  string         `json:"schemaVersion"`
	Version string         `json:"version"`
	Commit  string         `json:"commit"`
	Issued  string         `json:"issuedAtUtc"`
	Expires string         `json:"expiresAtUtc"`
	Targets []gaTarget0361 `json:"targets"`
}
type gaTrace0361 struct {
	Schema      string `json:"schemaVersion"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Target      string `json:"target"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	Actual      bool   `json:"actualExecution"`
	Simulated   bool   `json:"simulated"`
	ArtifactSHA string `json:"artifactSha256"`
	ExecutionID string `json:"executionId"`
}
type gaReceipt0361 struct {
	Schema       string `json:"schemaVersion"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	Status       string `json:"status"`
	ApprovalSHA  string `json:"approvalSha256"`
	PublicKeySHA string `json:"operatorPublicKeySha256"`
	Targets      []struct {
		Target     string `json:"target"`
		Binary     string `json:"binary"`
		BinarySHA  string `json:"binarySha256"`
		Package    string `json:"package"`
		PackageSHA string `json:"packageSha256"`
		Checks     int    `json:"checksPassed"`
	} `json:"targets"`
}

func gaTargetsRequired0361(v string) bool {
	triple, ok := parseVersionTriple0158(v)
	return ok && compareVersionTriple0158(triple, [3]int{0, 36, 1}) >= 0
}

// Отклоняйте повторяющиеся имена полей JSON, а не только неизвестные поля: независимый
// оператор и подписант не должны по-разному трактовать неоднозначность.
func gaUniqueJSON0361(raw []byte) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	var parse func() error
	parse = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, isDelim := tok.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("Обнаружен дубликат: «or non-string GA JSON field» %v", key)
				}
				seen[name] = true
				if err := parse(); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		case '[':
			for d.More() {
				if err := parse(); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		default:
			return errors.New("Неожиданное значение: разделитель JSON")
		}
	}
	if err := parse(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("После JSON-документа GA обнаружены лишние данные")
	}
	return nil
}

func gaDecode0361(raw []byte, out interface{}) error {
	if err := gaUniqueJSON0361(raw); err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Обнаружены лишние данные после: JSON содержимое")
	}
	return nil
}

func gaRead0361(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > limit {
		return nil, fmt.Errorf("Файл GA пуст, слишком велик либо не является обычным файлом: %s", path)
	}
	return os.ReadFile(path)
}
func gaSHA0361(data []byte) string { sha := sha256.Sum256(data); return hex.EncodeToString(sha[:]) }
func gaFileSHA0361(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 {
		return "", fmt.Errorf("Отсутствует: «or unsafe release artifact»: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func gaTargetPaths0361(version, target string) (string, string) {
	pair := strings.Split(target, "-")
	if len(pair) != 2 {
		return "", ""
	}
	osname, arch := pair[0], pair[1]
	switch osname {
	case "windows":
		return "launcher-desktop-windows-" + arch + ".exe", "launcher-desktop-" + version + "-windows-" + arch + ".zip"
	case "linux":
		return "launcher-desktop-linux-" + arch, "launcher-linux-" + arch + "-" + version + ".tar.gz"
	case "darwin":
		return "launcher-desktop-macos-" + arch, "launcher-desktop-" + version + "-macos-" + arch + ".zip"
	}
	return "", ""
}

func verifyGATargets0361(dir, version, commit string, releaseSigner ed25519.PublicKey) error {
	if !gaTargetsRequired0361(version) {
		return nil
	}
	if strings.ContainsAny(version, "-+") {
		return errors.New("GA 0.36.1+ BLOCKED: release: требуется «stable SemVer»")
	}
	if !gaCommit0361.MatchString(commit) {
		return errors.New("Для GA требуется точный SHA исходников в манифесте релиза")
	}
	evidence := strings.TrimSpace(os.Getenv("LAUNCHER_GA_EVIDENCE_DIR"))
	keyFile := strings.TrimSpace(os.Getenv("LAUNCHER_GA_TRUSTED_PUBLIC_KEY_FILE"))
	if evidence == "" || keyFile == "" {
		return errors.New("Требуется: «GA 0.36.1+ BLOCKED: independent evidence and pinned operator key»")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, keyFile); err != nil {
		return err
	}
	pubRaw, err := gaRead0361(keyFile, 4096)
	if err != nil {
		return err
	}
	keyHex := strings.TrimSpace(string(pubRaw))
	if len(keyHex) != 64 {
		return errors.New("operator GA key: требуется «32-byte raw public key hex»")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return err
	}
	if ed25519.PublicKey(keyBytes).Equal(releaseSigner) {
		return errors.New("ключ подписи выпуска не должен использоваться как независимый ключ оператора для приёмки GA")
	}
	approvalRaw, err := gaRead0361(filepath.Join(evidence, "approval.json"), 1<<20)
	if err != nil {
		return err
	}
	signatureRaw, err := gaRead0361(filepath.Join(evidence, "approval.sig"), 256)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(signatureRaw)))
	if err != nil || len(sig) != 64 || !ed25519.Verify(ed25519.PublicKey(keyBytes), append([]byte(gaTargetsDomain0361), approvalRaw...), sig) {
		return errors.New("GA 0.36.1+: операция заблокирована — независимое одобрение Ed25519 отсутствует или недействительно (устаревшая подпись не принимается)")
	}
	var approval gaApproval0361
	if err := gaDecode0361(approvalRaw, &approval); err != nil {
		return err
	}
	if approval.Schema != "launcher.ga.targets.v2" || approval.Version != version || approval.Commit != commit || len(approval.Targets) != 6 {
		return errors.New("Подпись GA не закрепляет точные версию, коммит и шесть целевых платформ")
	}
	issued, err := time.Parse("2006-01-02T15:04:05Z", approval.Issued)
	if err != nil || issued.UTC().Format("2006-01-02T15:04:05Z") != approval.Issued {
		return errors.New("Некорректная дата выдачи")
	}
	expires, err := time.Parse("2006-01-02T15:04:05Z", approval.Expires)
	if err != nil || expires.UTC().Format("2006-01-02T15:04:05Z") != approval.Expires {
		return errors.New("Некорректная дата истечения срока")
	}
	now := time.Now().UTC()
	if issued.After(now) || expires.Before(now) || expires.Sub(issued) > 7*24*time.Hour || !expires.After(issued) {
		return errors.New("Разрешение оператора GA истекло, ещё не действует или имеет чрезмерный срок")
	}
	storedApproval, err := gaRead0361(filepath.Join(dir, "GA_TARGET_APPROVAL.json"), 1<<20)
	if err != nil {
		return err
	}
	storedSig, err := gaRead0361(filepath.Join(dir, "GA_TARGET_APPROVAL.sig"), 256)
	if err != nil {
		return err
	}
	if string(storedApproval) != string(approvalRaw) || strings.TrimSpace(string(storedSig)) != strings.TrimSpace(string(signatureRaw)) {
		return errors.New("«staged signed approval» не совпадает с «operator evidence»")
	}
	receiptRaw, err := gaRead0361(filepath.Join(dir, "GA_VERIFIED_TARGETS.json"), 1<<20)
	if err != nil {
		return err
	}
	var receipt gaReceipt0361
	if err := gaDecode0361(receiptRaw, &receipt); err != nil {
		return err
	}
	if receipt.Schema != "launcher.ga.verified-targets.v2" || receipt.Status != "approved-for-release-signing" || receipt.Version != version || receipt.Commit != commit || receipt.ApprovalSHA != gaSHA0361(approvalRaw) || receipt.PublicKeySHA != gaSHA0361(keyBytes) || len(receipt.Targets) != 6 {
		return errors.New("Проверенная квитанция GA не соответствует независимому одобрению")
	}
	seen := map[string]bool{}
	expected := map[string]bool{}
	for _, t := range gaTargetNames0361 {
		expected[t] = true
	}
	for _, t := range approval.Targets {
		if !expected[t.Target] || seen[t.Target] || t.Status != "certified" || !gaHex0361.MatchString(t.BinarySHA) || !gaHex0361.MatchString(t.PackageSHA) || len(t.Checks) != len(gaCheckNames0361) {
			return fmt.Errorf("Целевая платформа GA отсутствует, дублируется или описана неполностью: %s", t.Target)
		}
		seen[t.Target] = true
		binaryName, packageName := gaTargetPaths0361(version, t.Target)
		binarySHA, err := gaFileSHA0361(filepath.Join(dir, binaryName))
		if err != nil {
			return err
		}
		packageSHA, err := gaFileSHA0361(filepath.Join(dir, packageName))
		if err != nil {
			return err
		}
		if binarySHA != t.BinarySHA || packageSHA != t.PackageSHA {
			return fmt.Errorf("Фактический пакет или исполняемый файл GA не совпадает с ожидаемым: %s", t.Target)
		}
		matching := false
		for _, r := range receipt.Targets {
			if r.Target == t.Target {
				if matching || r.Binary != binaryName || r.Package != packageName || r.BinarySHA != t.BinarySHA || r.PackageSHA != t.PackageSHA || r.Checks != len(gaCheckNames0361) {
					return fmt.Errorf("Несовпадение: подтверждение приёмки GA: %s", t.Target)
				}
				matching = true
			}
		}
		if !matching {
			return fmt.Errorf("Целевая платформа GA отсутствует в квитанции: %s", t.Target)
		}
		for _, check := range gaCheckNames0361 {
			meta, ok := t.Checks[check]
			if !ok || !gaHex0361.MatchString(meta.SHA) {
				return fmt.Errorf("Отсутствует проверка GA: %s/%s", t.Target, check)
			}
			raw, err := gaRead0361(filepath.Join(evidence, "targets", t.Target, check+".json"), 1<<20)
			if err != nil {
				return err
			}
			if gaSHA0361(raw) != meta.SHA {
				return fmt.Errorf("Изменилась запись выполнения GA: %s/%s", t.Target, check)
			}
			var trace gaTrace0361
			if err := gaDecode0361(raw, &trace); err != nil {
				return err
			}
			if trace.Schema != "launcher.ga.execution.v2" || trace.Version != version || trace.Commit != commit || trace.Target != t.Target || trace.Kind != check || trace.Status != "passed" || !trace.Actual || trace.Simulated || trace.ArtifactSHA != t.BinarySHA || !gaExecutionID0361.MatchString(trace.ExecutionID) {
				return fmt.Errorf("Проверка GA не подтверждена реальным запуском или использует неверный бинарный файл: %s/%s", t.Target, check)
			}
		}
	}
	if len(seen) != 6 {
		return errors.New("Приёмка GA не охватывает все шесть целевых платформ")
	}
	// Не допускайте незаметной поставки седьмого платформенного архива вне выданного разрешения.
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	permitted := map[string]bool{"launcher-desktop-" + version + "-windows-amd64.zip": true, "launcher-desktop-" + version + "-macos-universal.zip": true}
	for _, t := range gaTargetNames0361 {
		b, p := gaTargetPaths0361(version, t)
		permitted[b] = true
		permitted[p] = true
	}
	for _, item := range items {
		name := item.Name()
		if (strings.HasPrefix(name, "launcher-desktop-windows-") || strings.HasPrefix(name, "launcher-desktop-linux-") || strings.HasPrefix(name, "launcher-desktop-macos-") || strings.HasPrefix(name, "launcher-linux-") || strings.HasPrefix(name, "launcher-desktop-"+version+"-windows-") || strings.HasPrefix(name, "launcher-desktop-"+version+"-macos-")) && !permitted[name] && (strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, "-riscv64") || strings.HasSuffix(name, "-riscv64.exe")) {
			return fmt.Errorf("Артефакт для неподтверждённой целевой платформы: %s", name)
		}
	}
	return nil
}
