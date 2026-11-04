package trustbaseline

import (
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Решения вычисляются по авторитетному состоянию устройства/сеанса на сервере.
// В версии 0.31.1 нет проверки происхождения удалённого TPM / Secure Enclave. В
// частности, никакое сохранённое устаревшее значение или присланная клиентом метка оборудования не может
// повысить его результат до статуса удалённо проверенного.
const (
	Standard = "standard"
	Strict   = "strict"
	Allow    = "allow"
	Deny     = "deny"
)

type Decision struct {
	Profile        string   `json:"profile"`
	Result         string   `json:"result"`
	ReasonCodes    []string `json:"reasonCodes"`
	RecoveryAction string   `json:"recoveryAction,omitempty"`
}

func isMacPlatform0316(value string) bool {
	platform := strings.ToLower(strings.TrimSpace(value))
	return platform == "darwin" || platform == "macos" || platform == "macintosh" ||
		platform == "macintel" || platform == "macppc" || strings.HasPrefix(platform, "mac os")
}

func Evaluate(device model.TrustedDevice, sessionBound bool, now time.Time) model.TrustAssessment {
	now = now.UTC()
	a := model.TrustAssessment{
		KeyPossession: "not-verified", LocalHardwareBinding: "not-verified",
		RemoteHardwareProvenance: "not-verified", ArtifactIntegrity: "unknown",
		RuntimeEvidence: "none", PolicyDecision: Deny, AssessedAt: now,
	}
	reasons := make([]string, 0, 5)
	active := device.Status == "active" && device.TrustState == "verified"
	if active && device.KeyFingerprint != "" && (device.KeyAlgorithm == "ed25519" || device.KeyAlgorithm == "p256") {
		a.KeyPossession = "verified"
	} else {
		reasons = append(reasons, "device-not-verified")
	}
	if !sessionBound {
		reasons = append(reasons, "session-device-binding-missing")
	}
	// Локальные метки KSP/TPM передаются регистрирующимся клиентом и не являются
	// доказательством оборудования, проверяемым сервером. Сообщать о них только как о заявлениях.
	if device.KeyBinding == "hardware" && device.KeyAlgorithm == "p256" && strings.TrimSpace(device.HardwareProvider) != "" {
		a.LocalHardwareBinding = "client-reported"
	}
	if device.AttestationState == "verified" {
		if device.AttestedAt.IsZero() || device.AttestedAt.After(now) || !device.AttestationExpiresAt.After(now) || !device.AttestationExpiresAt.After(device.AttestedAt) || device.AttestationExpiresAt.Sub(device.AttestedAt) > 12*time.Hour+time.Minute || device.AttestationMethod != "challenge-response-v1" {
			reasons = append(reasons, "challenge-response-expired-or-invalid")
		} else {
			a.EvidenceExpiresAt = device.AttestationExpiresAt
		}
	} else if device.AttestationState == "expired" {
		reasons = append(reasons, "challenge-response-expired-or-invalid")
	}
	standardReasons := append([]string(nil), reasons...)
	standard := Decision{Profile: Standard, Result: Deny, ReasonCodes: standardReasons}
	if a.KeyPossession == "verified" && sessionBound {
		standard.Result = Allow
		standard.ReasonCodes = []string{}
		a.PolicyDecision = Allow
	} else {
		standard.RecoveryAction = "login-or-verify-device"
	}
	strictReasons := append([]string(nil), standardReasons...)
	// Пока 0.31.2+ реально не проверяет доверенный корень, точный ключ, nonce и
	// эпоху привязки, строгий уровень нельзя выдавать даже для старой строки с меткой
	// «verified» или локального ключа, хранящегося в TPM.
	strictReasons = append(strictReasons, "remote-hardware-verifier-unavailable", "guard-runtime-evidence-unavailable")
	if isMacPlatform0316(device.Platform) {
		strictReasons = append(strictReasons, "macos-device-key-provenance-unsupported", "macos-app-attest-not-bound-to-device-identity")
	}
	recovery := "use-standard-profile-or-supported-verified-device"
	if isMacPlatform0316(device.Platform) {
		recovery = "use-standard-profile-or-recover-device-with-fresh-passkey-then-reattest"
	}
	strict := Decision{Profile: Strict, Result: Deny, ReasonCodes: strictReasons, RecoveryAction: recovery}
	a.ReasonCodes = strictReasons
	a.ProfileDecisions = map[string]model.TrustProfileDecision{
		Standard: {Profile: standard.Profile, Result: standard.Result, ReasonCodes: standard.ReasonCodes, RecoveryAction: standard.RecoveryAction},
		Strict:   {Profile: strict.Profile, Result: strict.Result, ReasonCodes: strict.ReasonCodes, RecoveryAction: strict.RecoveryAction},
	}
	return a
}

// EvaluateWithHardwareEvidence повышает доверие к происхождению оборудования только по
// проверенному сервером результату TPM Certify, чей активный корень, эпоха и сеанс
// были повторно проверены вызывающим. Guard Runtime остаётся независимо непроверенным.
func EvaluateWithHardwareEvidence(device model.TrustedDevice, sessionBound bool, evidence model.DeviceHardwareEvidence, now time.Time) model.TrustAssessment {
	a := Evaluate(device, sessionBound, now)
	if !sessionBound || a.KeyPossession != "verified" || evidence.DeviceID != device.ID || evidence.UserID != device.UserID || evidence.KeyFingerprint != device.KeyFingerprint || evidence.RootID == "" || evidence.AKFingerprint == "" || evidence.VerifiedAt.After(now) || !evidence.ExpiresAt.After(now) {
		return a
	}
	a.RemoteHardwareProvenance = "tpm-ak-certified"
	a.EvidenceExpiresAt = evidence.ExpiresAt
	reasons := make([]string, 0, len(a.ReasonCodes))
	for _, v := range a.ReasonCodes {
		if v != "remote-hardware-verifier-unavailable" {
			reasons = append(reasons, v)
		}
	}
	a.ReasonCodes = reasons
	strict := a.ProfileDecisions[Strict]
	strict.ReasonCodes = append([]string(nil), reasons...)
	a.ProfileDecisions[Strict] = strict
	return a
}
