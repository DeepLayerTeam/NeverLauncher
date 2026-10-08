package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const gameplayTrustPolicy0127 = "session-device-risk-v1"

type gameplayTrustDecision0127 struct {
	Allowed         bool   `json:"allowed"`
	Reason          string `json:"reason"`
	Policy          string `json:"policy"`
	TrustedDeviceID string `json:"trustedDeviceId,omitempty"`
	BindingEpoch    int64  `json:"bindingEpoch,omitempty"`
	RiskState       string `json:"riskState,omitempty"`
	RiskScore       int    `json:"riskScore,omitempty"`
	RiskAction      string `json:"riskAction,omitempty"`
}

func gameplayTrustDeny0127(reason string, rec authSessionRecord) gameplayTrustDecision0127 {
	return gameplayTrustDecision0127{
		Allowed:         false,
		Reason:          reason,
		Policy:          gameplayTrustPolicy0127,
		TrustedDeviceID: strings.TrimSpace(rec.TrustedDeviceID),
		BindingEpoch:    rec.BindingEpoch,
		RiskState:       normalizeRiskState118(rec.RiskState),
		RiskScore:       rec.RiskScore,
		RiskAction:      firstNonEmpty(rec.RiskAction, "allow"),
	}
}

func gameplayTrustAllow0127(rec authSessionRecord) gameplayTrustDecision0127 {
	return gameplayTrustDecision0127{
		Allowed:         true,
		Reason:          "trusted_session",
		Policy:          gameplayTrustPolicy0127,
		TrustedDeviceID: strings.TrimSpace(rec.TrustedDeviceID),
		BindingEpoch:    rec.BindingEpoch,
		RiskState:       normalizeRiskState118(rec.RiskState),
		RiskScore:       rec.RiskScore,
		RiskAction:      firstNonEmpty(rec.RiskAction, "allow"),
	}
}

// evaluateGameplayTrust0127 validates the current server-authoritative Never
// session against the device/binding snapshot attached to a Minecraft or
// ServerBridge credential. It deliberately does not call observe(): server-side
// /hasJoined and plugin validation requests originate from the game server, not
// the player's launcher, and therefore must never mutate player IP/UA risk.
func (s Server) evaluateGameplayTrust0127(r *http.Request, userID, sessionID, expectedDeviceID string, expectedBindingEpoch int64, requireBoundDevice bool) (authSessionRecord, gameplayTrustDecision0127) {
	rec, ok := s.State.AuthSessions.get(strings.TrimSpace(sessionID), strings.TrimSpace(userID))
	if !ok {
		return authSessionRecord{}, gameplayTrustDeny0127("parent_session_inactive", authSessionRecord{})
	}
	rec, err := s.reconcileSessionDeviceRisk0126(r, rec)
	if err != nil {
		if errors.Is(err, errSessionRiskDenied0126) {
			return authSessionRecord{}, gameplayTrustDeny0127("session_risk_revoked", rec)
		}
		return authSessionRecord{}, gameplayTrustDeny0127("session_risk_unavailable", rec)
	}
	if rec.BindingEpoch < 1 {
		rec.BindingEpoch = 1
	}
	expectedDeviceID = strings.TrimSpace(expectedDeviceID)
	if requireBoundDevice && strings.TrimSpace(rec.TrustedDeviceID) == "" {
		return rec, gameplayTrustDeny0127("trusted_device_required", rec)
	}
	if requireBoundDevice && (expectedDeviceID == "" || expectedBindingEpoch < 1) {
		return rec, gameplayTrustDeny0127("credential_trust_snapshot_missing", rec)
	}
	if expectedBindingEpoch > 0 && rec.BindingEpoch != expectedBindingEpoch {
		return rec, gameplayTrustDeny0127("session_binding_changed", rec)
	}
	if expectedDeviceID != "" && strings.TrimSpace(rec.TrustedDeviceID) != expectedDeviceID {
		return rec, gameplayTrustDeny0127("session_device_changed", rec)
	}
	if requireBoundDevice && strings.TrimSpace(rec.TrustedDeviceID) == "" {
		return rec, gameplayTrustDeny0127("trusted_device_required", rec)
	}
	if strings.TrimSpace(rec.TrustedDeviceID) != "" {
		if rec.DeviceTrustState != "verified" {
			return rec, gameplayTrustDeny0127("trusted_device_unverified", rec)
		}
		device, err := s.Repo.GetTrustedDevice(rec.UserID, rec.TrustedDeviceID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return rec, gameplayTrustDeny0127("trusted_device_missing", rec)
			}
			return rec, gameplayTrustDeny0127("trusted_device_unavailable", rec)
		}
		if device.Status != "active" || device.TrustState != "verified" {
			return rec, gameplayTrustDeny0127("trusted_device_revoked", rec)
		}
	}
	switch firstNonEmpty(rec.RiskAction, "allow") {
	case "revoke":
		return rec, gameplayTrustDeny0127("session_risk_revoked", rec)
	case "reattest":
		return rec, gameplayTrustDeny0127("device_reattest_required", rec)
	case "step-up":
		return rec, gameplayTrustDeny0127("session_step_up_required", rec)
	case "allow":
		// continue
	default:
		return rec, gameplayTrustDeny0127("session_risk_unknown", rec)
	}
	return rec, gameplayTrustAllow0127(rec)
}

func gameplayTrustPermanentFailure0127(reason string) bool {
	switch reason {
	case "parent_session_inactive", "credential_trust_snapshot_missing", "session_binding_changed", "session_device_changed", "trusted_device_missing", "trusted_device_revoked", "session_risk_revoked":
		return true
	default:
		return false
	}
}

func (s Server) writeGameplayTrustRequirement0127(w http.ResponseWriter, decision gameplayTrustDecision0127) {
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": map[string]any{
		"code":            http.StatusPreconditionRequired,
		"message":         "Minecraft/ServerBridge trust policy не выполнена",
		"reason":          decision.Reason,
		"trustPolicy":     decision.Policy,
		"trustedDeviceId": decision.TrustedDeviceID,
		"bindingEpoch":    decision.BindingEpoch,
		"riskState":       decision.RiskState,
		"riskScore":       decision.RiskScore,
		"riskAction":      decision.RiskAction,
	}})
}
