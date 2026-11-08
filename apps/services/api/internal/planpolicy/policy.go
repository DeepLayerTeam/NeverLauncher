package planpolicy02412

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// Доверенный оператор подписывает точные байты политики автономно. Ни вызывающий, ни
// узел ServerBridge не могут задавать ключ подписи или ослаблять allowlist.
const Domain = "Launcher-ServerBridge-Plan-Policy-v1\n"

type Envelope struct {
	SchemaVersion string `json:"schemaVersion"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}
type AllowedPlan struct {
	ServerID         string `json:"serverId"`
	ProjectID        string `json:"projectId"`
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	ReleaseSignature string `json:"releaseSignature"`
	CatalogDigest    string `json:"catalogDigest"`
	PlanSHA256       string `json:"planSha256"`
}
type Policy struct {
	SchemaVersion          string        `json:"schemaVersion"`
	Epoch                  uint64        `json:"epoch"`
	IssuedAt               string        `json:"issuedAt"`
	ExpiresAt              string        `json:"expiresAt"`
	RequireContinuousGuard bool          `json:"requireContinuousGuard"`
	AllowedPlans           []AllowedPlan `json:"allowedPlans"`
}

func isHexLength(v string, n int) bool {
	if len(v) != n {
		return false
	}
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == n/2 && v == strings.ToLower(v)
}
func Matches(policy Policy, server, project, profile, channel, release, catalog, plan string) bool {
	for _, a := range policy.AllowedPlans {
		if a.ServerID == server && a.ProjectID == project && a.ProfileID == profile && a.Channel == channel && a.ReleaseSignature == release && a.CatalogDigest == catalog && a.PlanSHA256 == plan {
			return true
		}
	}
	return false
}

// Конфигурация по умолчанию намеренно использует устаревшее поведение; перед
// включением защищённого режима входа в production оператор должен задать
// REQUIRE_PLAN_POLICY=1.
func Required() bool {
	return os.Getenv("LAUNCHER_SERVERBRIDGE_REQUIRE_PLAN_POLICY") == "1" || os.Getenv("LAUNCHER_SERVERBRIDGE_PLAN_POLICY_FILE") != "" || os.Getenv("LAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY") != ""
}
func Load(now time.Time) (Policy, error) {
	var out Policy
	path := strings.TrimSpace(os.Getenv("LAUNCHER_SERVERBRIDGE_PLAN_POLICY_FILE"))
	pin := strings.TrimSpace(os.Getenv("LAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY"))
	if path == "" || pin == "" {
		return out, errors.New("Подписанная политика плана ServerBridge не подготовлена")
	}
	key, e := hex.DecodeString(pin)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return out, errors.New("Некорректное значение: закреплённый открытый ключ политики ServerBridge")
	}
	info, e := os.Lstat(path)
	if e != nil {
		return out, e
	}
	if !info.Mode().IsRegular() || info.Size() > 256*1024 {
		return out, errors.New("Небезопасный объект: ServerBridge файл политики")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return out, e
	}
	var env Envelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return out, e
	}
	if env.SchemaVersion != "1.0" {
		return out, errors.New("Не поддерживается: «конверт политики плана»")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if e != nil || len(payload) == 0 || len(payload) > 192*1024 {
		return out, errors.New("Некорректное значение: «данные политики плана»")
	}
	sig, e := hex.DecodeString(env.Signature)
	if e != nil || len(sig) != 64 || !ed25519.Verify(key, append([]byte(Domain), payload...), sig) {
		return out, errors.New("Некорректное значение: «подпись политики ServerBridge»")
	}
	if e = json.Unmarshal(payload, &out); e != nil {
		return out, e
	}
	if out.SchemaVersion != "1.0" || out.Epoch == 0 || !out.RequireContinuousGuard || len(out.AllowedPlans) == 0 || len(out.AllowedPlans) > 2048 {
		return out, errors.New("некорректная или небезопасная политика плана")
	}
	from, e := time.Parse(time.RFC3339, out.IssuedAt)
	if e != nil {
		return out, e
	}
	until, e := time.Parse(time.RFC3339, out.ExpiresAt)
	if e != nil {
		return out, e
	}
	if from.After(now.Add(5*time.Minute)) || !until.After(now) || until.Sub(from) > 30*24*time.Hour || !until.After(from) {
		return out, errors.New("Политика ServerBridge находится вне срока действия")
	}
	seen := make(map[string]struct{}, len(out.AllowedPlans))
	for _, a := range out.AllowedPlans {
		if !isHexLength(a.ReleaseSignature, 128) || !isHexLength(a.CatalogDigest, 64) || !isHexLength(a.PlanSHA256, 64) || a.ServerID == "" || a.ProjectID == "" || a.ProfileID == "" || a.Channel == "" || strings.ContainsAny(a.ServerID+a.ProjectID+a.ProfileID+a.Channel, "\n\r") {
			return out, errors.New("Некорректное значение: запись списка разрешений подписанного плана")
		}
		k := a.ServerID + "/" + a.ProjectID + "/" + a.ProfileID + "/" + a.Channel + "/" + a.PlanSHA256
		if _, ok := seen[k]; ok {
			return out, errors.New("Обнаружен дубликат: запись списка разрешений подписанного плана")
		}
		seen[k] = struct{}{}
	}
	return out, nil
}
