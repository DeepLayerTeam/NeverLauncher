package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const operationsGAFile0460 = "OPERATIONS_GA_0460.json"
const operationsGASig0460 = "OPERATIONS_GA_0460.sig"
const operationsGADomain0460 = "neverlauncher.operations-ga.0460.v1\x00"

func operationsGARequired0460(version string) bool {
	v, ok := parseVersionTriple0158(version)
	return ok && compareVersionTriple0158(v, [3]int{0, 46, 0}) >= 0
}

type operationsGATarget0460 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type operationsGAApproval0460 struct {
	Schema          string                            `json:"schema"`
	Version         string                            `json:"version"`
	SourceCommit    string                            `json:"sourceCommit"`
	IssuedAt        string                            `json:"issuedAt"`
	Operator        string                            `json:"operator"`
	SourceMachine   string                            `json:"sourceMachine"`
	RestoreMachine  string                            `json:"restoreMachine"`
	StageReceipts   map[string]string                 `json:"stageReceipts"`
	OpenApiV1Sha256 string                            `json:"openApiV1Sha256"`
	Targets         map[string]operationsGATarget0460 `json:"targets"`
	Scope           string                            `json:"scope"`
}

func operationsGARead0460(dir, name string, max int64) ([]byte, error) {
	p := filepath.Join(dir, name)
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
		return nil, fmt.Errorf("Небезопасное значение: «operations GA file»: %s", name)
	}
	return os.ReadFile(p)
}

// Проверяются байты финального каталога выпуска и внешний закреплённый ключ оператора.
// Неподписанные квитанции и ключ из самого пакета не вправе разрешать операции GA.
// Вызывается и при подписании, и при проверке потребителем.
func verifyOperationsGA0460(dir, version string, releasePublic ed25519.PublicKey) error {
	if !operationsGARequired0460(version) {
		return nil
	}
	keyPath := strings.TrimSpace(os.Getenv("LAUNCHER_OPERATIONS_GA_TRUSTED_PUBLIC_KEY_FILE"))
	if keyPath == "" {
		return errors.New("Требуется: «0.46.0 GA BLOCKED: independent operator trust anchor»")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, keyPath); err != nil {
		return err
	}
	pub, err := loadEd25519PublicKey(keyPath)
	if err != nil {
		return fmt.Errorf("Корень доверия оператора: %w", err)
	}
	if len(releasePublic) == ed25519.PublicKeySize && string(pub) == string(releasePublic) {
		return errors.New("Оператор и подписывающая сторона релиза должны использовать независимые ключи Ed25519")
	}
	raw, err := operationsGARead0460(dir, operationsGAFile0460, 64*1024)
	if err != nil {
		return err
	}
	encoded, err := operationsGARead0460(dir, operationsGASig0460, 1024)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, append([]byte(operationsGADomain0460), raw...), sig) {
		return errors.New("Ошибка: «independent operations GA signature»")
	}
	var a operationsGAApproval0460
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	manifestRaw, err := operationsGARead0460(dir, "RELEASE_MANIFEST.json", 16*1024*1024)
	if err != nil {
		return err
	}
	var m struct {
		Version       string   `json:"version"`
		SourceCommit  string   `json:"sourceCommit"`
		RequiredFiles []string `json:"requiredFiles"`
		Artifacts     []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Status   string `json:"status"`
			SHA256   string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return err
	}
	if a.Schema != "neverlauncher.operations-ga.0460.v1" || a.Version != version || m.Version != version || a.SourceCommit != m.SourceCommit || !regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`).MatchString(a.SourceCommit) {
		return errors.New("«operations GA» не совпадает с «exact source commit and version»")
	}
	issued, err := time.Parse(time.RFC3339Nano, a.IssuedAt)
	if err != nil || time.Since(issued) > 14*24*time.Hour || time.Until(issued) > 5*time.Minute {
		return errors.New("Эксплуатационная приёмка GA просрочена либо имеет неверную временную метку")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if a.Operator == "" || a.SourceMachine == a.RestoreMachine || !hex64.MatchString(a.SourceMachine) || !hex64.MatchString(a.RestoreMachine) || !hex64.MatchString(a.OpenApiV1Sha256) {
		return errors.New("Некорректное значение: «independent operator, hosts or frozen API fingerprint»")
	}
	// Байты утверждённого API v1 должны совпадать с исходными байтами, закреплёнными в BOM выпуска;
	// произвольного отдельного дайджеста API в утверждении недостаточно.
	bomRaw, err := operationsGARead0460(dir, releaseBOMFile03214, 16*1024*1024)
	if err != nil {
		return fmt.Errorf("Закреплённый BOM API: %w", err)
	}
	var bom struct {
		Components []struct {
			SourceFile   string `json:"sourceFile"`
			SourceSHA256 string `json:"sourceSha256"`
		} `json:"components"`
	}
	if err := json.Unmarshal(bomRaw, &bom); err != nil {
		return err
	}
	apiEntries := 0
	for _, c := range bom.Components {
		if c.SourceFile == "schemas/openapi.yaml" {
			apiEntries++
			if c.SourceSHA256 != a.OpenApiV1Sha256 {
				return errors.New("Одобренный API v1 отличается от содержимого исходных данных BOM релиза")
			}
		}
	}
	if apiEntries != 1 {
		return errors.New("BOM релиза должен закреплять ровно один основной контракт API")
	}
	if a.Scope != "Фактическая независимая эксплуатационная приёмка; RPO проверен только на контрольных данных, без утверждений об отказоустойчивости физических узлов и неизмеренного RPO нагрузки" {
		return errors.New("Не поддерживается: «operations GA evidence scope»")
	}
	requiredStages := []string{"install-standard", "upgrade-standard", "restore-standard", "failover-network-ha"}
	if len(a.StageReceipts) != len(requiredStages) {
		return errors.New("Требуется: «all four independent operational receipts»")
	}
	for _, stage := range requiredStages {
		if !hex64.MatchString(a.StageReceipts[stage]) {
			return fmt.Errorf("Некорректное значение: «operational receipt hash»: %s", stage)
		}
	}
	if len(a.Targets) != 6 {
		return errors.New("Эксплуатационная приёмка GA должна подтверждать шесть пакетов платформ")
	}
	for _, t := range distributionTargets04511(version) {
		r, ok := a.Targets[t.target]
		if !ok || r.Name != t.packageFile || !hex64.MatchString(r.SHA256) {
			return fmt.Errorf("Отсутствует: «operations GA target»: %s", t.target)
		}
		h, e := distributionHash04511(dir, t.packageFile)
		if e != nil {
			return e
		}
		if h != r.SHA256 {
			return fmt.Errorf("Обнаружено изменение: «operations GA final package»: %s", t.target)
		}
	}
	for _, name := range []string{operationsGAFile0460, operationsGASig0460} {
		required := false
		artifact := false
		for _, r := range m.RequiredFiles {
			if r == name {
				required = true
			}
		}
		for _, f := range m.Artifacts {
			if f.Name == name && f.Required && f.Status == "present" {
				h, _, e := hashFile(filepath.Join(dir, name))
				if e == nil && h == f.SHA256 {
					artifact = true
				}
			}
		}
		if !required || !artifact {
			return fmt.Errorf("Эксплуатационная приёмка GA не привязана к подписанному манифесту релиза: %s", name)
		}
	}
	return nil
}
