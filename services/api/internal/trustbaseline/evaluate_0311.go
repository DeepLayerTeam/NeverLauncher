package trustbaseline

import (
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Decisions are computed from authoritative server-side device/session state.
// 0.31.1 has no remote TPM / Secure Enclave key provenance verifier. In
// particular no persisted legacy value or client-supplied hardware label can
// upgrade its result to remotely verified.
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
	// Local KSP/TPM labels come from the registering client and are not
	// server-verifiable hardware evidence. Report them as claims only.
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
	// Until 0.31.2+ actually verifies a trusted root, exact key, nonce and
	// binding epoch, strict cannot be granted even for a legacy row marked
	// "verified" or a locally TPM-backed key.
	strictReasons = append(strictReasons, "remote-hardware-verifier-unavailable", "guard-runtime-evidence-unavailable")
	platform := strings.ToLower(strings.TrimSpace(device.Platform))
	if platform == "darwin" || platform == "macos" || strings.HasPrefix(platform, "mac os") {
		strictReasons = append(strictReasons, "macos-device-key-provenance-unsupported")
	}
	strict := Decision{Profile: Strict, Result: Deny, ReasonCodes: strictReasons, RecoveryAction: "use-standard-profile-or-supported-verified-device"}
	a.ReasonCodes = strictReasons
	a.ProfileDecisions = map[string]model.TrustProfileDecision{
		Standard: {Profile: standard.Profile, Result: standard.Result, ReasonCodes: standard.ReasonCodes, RecoveryAction: standard.RecoveryAction},
		Strict:   {Profile: strict.Profile, Result: strict.Result, ReasonCodes: strict.ReasonCodes, RecoveryAction: strict.RecoveryAction},
	}
	return a
}

// EvaluateWithHardwareEvidence promotes hardware provenance only from a
// server-verified TPM Certify result whose active root, epoch and session have
// been rechecked by the caller. Guard runtime remains independently unverified.
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
