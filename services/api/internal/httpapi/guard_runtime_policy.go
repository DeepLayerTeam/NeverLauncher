package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Политика задаётся оператором на сервере, а не манифестом клиента. ModuleSetSHA256
// закрепляет точный разрешённый набор модулей; JavaMajor — семейство Runtime.
// Необязательные хеши кода/хуков могут дополнительно ограничивать развёртывание.
type guardRuntimeProfile0317 struct {
	JavaMajor       uint32 `json:"javaMajor"`
	ModuleSetSHA256 string `json:"moduleSetSha256"`
	CodeSetSHA256   string `json:"codeSetSha256,omitempty"`
	HookSetSHA256   string `json:"hookSetSha256,omitempty"`
}

var guardSemver0317 = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func guardRuntimePolicyRequired0317(version string) bool {
	// Некорректная версия не должна проходить как иной подписанный релиз.
	// Вызывающий также проверяет неправильные имена выпусков при загрузке
	// политики.
	matches := guardSemver0317.FindStringSubmatch(version)
	if matches == nil {
		return true // некорректные выпуски не могут отключить применение политик Guard
	}
	major, errA := strconv.ParseUint(matches[1], 10, 32)
	minor, errB := strconv.ParseUint(matches[2], 10, 32)
	patch, errC := strconv.ParseUint(matches[3], 10, 32)
	if errA != nil || errB != nil || errC != nil {
		return true // overflow also fails closed
	}
	return major > 0 || minor > 31 || (minor == 31 && patch >= 7)
}

func normalizeGuardRuntimeProfiles0317(input []guardRuntimeProfile0317) ([]guardRuntimeProfile0317, error) {
	if len(input) > 32 {
		return nil, errors.New("Слишком много профилей среды выполнения Guard (максимум 32)")
	}
	out := make([]guardRuntimeProfile0317, 0, len(input))
	seen := make(map[string]bool, len(input))
	for _, profile := range input {
		switch profile.JavaMajor {
		case 8, 16, 17, 21, 25:
		default:
			return nil, errors.New("Не поддерживается: «Java major in Guard runtime policy»")
		}
		profile.ModuleSetSHA256 = strings.ToLower(strings.TrimSpace(profile.ModuleSetSHA256))
		profile.CodeSetSHA256 = strings.ToLower(strings.TrimSpace(profile.CodeSetSHA256))
		profile.HookSetSHA256 = strings.ToLower(strings.TrimSpace(profile.HookSetSHA256))
		if !isSHA256Hex0134(profile.ModuleSetSHA256) {
			return nil, errors.New("moduleSetSha256: требуется хеш SHA-256")
		}
		if profile.CodeSetSHA256 != "" && !isSHA256Hex0134(profile.CodeSetSHA256) {
			return nil, errors.New("codeSetSha256: требуется хеш SHA-256")
		}
		if profile.HookSetSHA256 != "" && !isSHA256Hex0134(profile.HookSetSHA256) {
			return nil, errors.New("hookSetSha256: требуется хеш SHA-256")
		}
		key := fmt.Sprintf("%d:%s:%s:%s", profile.JavaMajor, profile.ModuleSetSHA256, profile.CodeSetSHA256, profile.HookSetSHA256)
		if seen[key] {
			return nil, errors.New("Обнаружен дубликат: «профиль Runtime»")
		}
		seen[key] = true
		out = append(out, profile)
	}
	return out, nil
}

// Хешируйте все действующие профили в объявленном порядке. Замена политики даже
// при той же версии релиза отзывает ранее выданные билеты на вход.
func guardRuntimePolicyDigest0317(profiles []guardRuntimeProfile0317) string {
	if len(profiles) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Launcher Guard Runtime Policy v1\n")
	for _, p := range profiles {
		fmt.Fprintf(&b, "%d:%s:%s:%s\n", p.JavaMajor, p.ModuleSetSHA256, p.CodeSetSHA256, p.HookSetSHA256)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func guardRuntimeMatches0317(profiles []guardRuntimeProfile0317, javaMajor uint32, moduleHash, codeHash, hookHash string) bool {
	for _, p := range profiles {
		if p.JavaMajor != javaMajor || !hmac.Equal([]byte(p.ModuleSetSHA256), []byte(moduleHash)) {
			continue
		}
		if p.CodeSetSHA256 != "" && !hmac.Equal([]byte(p.CodeSetSHA256), []byte(codeHash)) {
			continue
		}
		if p.HookSetSHA256 != "" && !hmac.Equal([]byte(p.HookSetSHA256), []byte(hookHash)) {
			continue
		}
		return true
	}
	return false
}

func verifyGuardRuntimePolicy0317(policy guardReleasePolicy0134, platform string, evidence guardContinuousEvidence01810) (string, error) {
	kind, err := guardPlatformKind0140(platform)
	if err != nil {
		return "", err
	}
	if kind != "windows" {
		return "", errors.New("continuous Guard runtime verification: требуется Windows")
	}
	profiles := policy.RuntimeProfiles[kind]
	if len(profiles) == 0 {
		return "", errors.New("«список разрешений Windows Guard Runtime»: не настроено")
	}
	if !guardRuntimeMatches0317(profiles, evidence.JavaMajor, evidence.ModuleSetSHA256, evidence.CodeSetSHA256, evidence.HookSetSHA256) {
		return "", errors.New("Версия Java или набор модулей, кода и хуков Runtime не одобрены")
	}
	return guardRuntimePolicyDigest0317(profiles), nil
}

func validGuardProcessID0317(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// После атомарного погашения одноразового билета выполняется повторная проверка;
// свидетельства не переживают отзыв корня, устройства, ключа, сеанса или политики.
// Подпись устройства в user-mode доказывает владение, но НЕ независимо измеренную
// целостность Runtime.
func (s Server) recheckContinuousGuardTicket0317(claims authClaims, ticket model.DeviceChallenge, now time.Time) error {
	if !validGuardProcessID0317(metadataString0121(ticket.Metadata, "processId")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "moduleSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "codeSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "hookSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "jvmStateSha256")) {
		return errors.New("Непрерывная проверка Guard: некорректные доказательства Runtime в билете")
	}
	major, err := strconv.ParseUint(metadataString0121(ticket.Metadata, "javaMajor"), 10, 32)
	if err != nil || major == 0 {
		return errors.New("Некорректное значение: «Continuous Guard ticket Java version»")
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		return errors.New("Недоступно: «Continuous Guard trusted device revoked or»")
	}
	state, _ := effectiveDeviceAttestation0124(device, now)
	if state != "verified" {
		return errors.New("Истёк срок действия: «Continuous Guard device attestation»")
	}
	// Не допускайте, чтобы устаревшие или ранее проверенные ключи устройств
	// переживали восстановление.
	if metadataString0121(ticket.Metadata, "deviceKeyFingerprint") != device.KeyFingerprint || device.KeyFingerprint == "" {
		return errors.New("Непрерывная проверка Guard: ключ устройства сменён или отозван")
	}
	version := metadataString0121(ticket.Metadata, "launcherVersion")
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		return errors.New("Недоступно: «Continuous Guard release policy»")
	}
	policy, ok := policies[version]
	if !ok {
		return errors.New("Отозвано: непрерывный релиз Guard")
	}
	allowed, _, err := policy.allowsArtifactPair0140(device.Platform, metadataString0121(ticket.Metadata, "guardSha256"), metadataString0121(ticket.Metadata, "launcherSha256"))
	if err != nil || !allowed {
		return errors.New("Непрерывная проверка Guard: релиз артефакта отозван")
	}
	evidence := guardContinuousEvidence01810{
		JavaMajor:       uint32(major),
		ModuleSetSHA256: metadataString0121(ticket.Metadata, "moduleSetSha256"),
		CodeSetSHA256:   metadataString0121(ticket.Metadata, "codeSetSha256"),
		HookSetSHA256:   metadataString0121(ticket.Metadata, "hookSetSha256"),
	}
	digest, err := verifyGuardRuntimePolicy0317(policy, device.Platform, evidence)
	if err != nil {
		return fmt.Errorf("Непрерывная проверка Guard: политика Runtime отозвана: %w", err)
	}
	if digest == "" || !hmac.Equal([]byte(digest), []byte(metadataString0121(ticket.Metadata, "runtimePolicySha256"))) {
		return errors.New("Непрерывная проверка Guard: политика Runtime изменилась после аттестации")
	}
	// TTL билета в репозитории является авторитетным; часы клиента и прежняя
	// оценка аппаратного корня не продлевают гарантии процесса.
	if ticket.CreatedAt.After(now.Add(guardAttestationClockSkew0134)) || !ticket.ExpiresAt.After(now) {
		return errors.New("Билет Continuous Guard просрочен или датирован будущим временем")
	}
	return nil
}
