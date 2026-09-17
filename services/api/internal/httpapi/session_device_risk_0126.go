package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

var errSessionRiskDenied0126 = errors.New("session risk policy denied request")

func sessionBindingClaimsMatch0126(claims authClaims, session authSessionRecord) bool {
	epoch := session.BindingEpoch
	if epoch < 1 {
		epoch = 1
	}
	// Compatibility for an access token minted by 0.12.5 immediately before
	// an in-place Backend upgrade. A subsequent bind/re-bind increments epoch,
	// so pre-binding/stale tokens cannot use this compatibility path.
	if claims.BindingEpoch != 0 && claims.BindingEpoch != epoch {
		return false
	}
	if claims.BindingEpoch == 0 && epoch != 1 {
		return false
	}
	sessionDevice := strings.TrimSpace(session.TrustedDeviceID)
	claimDevice := strings.TrimSpace(claims.TrustedDeviceID)
	if sessionDevice != claimDevice {
		return false
	}
	if sessionDevice == "" {
		return claimDevice == ""
	}
	return session.DeviceTrustState == "verified" && claims.DeviceTrustState == "verified"
}

func removeRiskReasons0126(existing []string, remove ...string) []string {
	drop := map[string]struct{}{}
	for _, v := range remove {
		drop[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	out := make([]string, 0, len(existing))
	for _, raw := range existing {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := drop[v]; ok {
			continue
		}
		out = append(out, v)
	}
	return mergeRiskReasons118(nil, out...)
}

func evaluateRiskReasons0126(reasons []string) (state string, score int, action string) {
	reasons = mergeRiskReasons118(nil, reasons...)
	network := false
	reattest := false
	compromise := false
	for _, reason := range reasons {
		switch reason {
		case "ip-changed":
			score += 25
			network = true
		case "user-agent-changed":
			score += 35
			network = true
		case "device-attestation-stale":
			score += 40
			reattest = true
		case "trusted-device-revoked", "trusted-device-missing", "trusted-device-invalid", "refresh-token-reuse":
			score = 100
			compromise = true
		default:
			// Unknown persisted security reasons are not silently downgraded.
			score += 25
			network = true
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case compromise || score >= 100:
		return "compromised", 100, "revoke"
	case reattest:
		// Device-key freshness cannot be satisfied by account MFA alone.
		// Prefer re-attestation over network step-up when both signals exist.
		return "elevated", score, "reattest"
	case network:
		return "elevated", score, "step-up"
	default:
		return "normal", 0, "allow"
	}
}

func recomputeSessionRisk0126(rec *authSessionRecord, now time.Time) {
	if rec == nil {
		return
	}
	previousState := normalizeRiskState118(rec.RiskState)
	previousScore := rec.RiskScore
	previousAction := firstNonEmpty(rec.RiskAction, "allow")
	state, score, action := evaluateRiskReasons0126(rec.RiskReasons)
	rec.RiskState = state
	rec.RiskScore = score
	rec.RiskAction = action
	rec.RiskEvaluatedAt = now.UTC()
	if state == "normal" {
		rec.RiskUpdatedAt = time.Time{}
	} else if rec.RiskUpdatedAt.IsZero() || state != previousState || score != previousScore || action != previousAction {
		// RiskUpdatedAt is the time the decision changed, not merely the last
		// evaluation. Otherwise every sensitive request would move the event
		// timestamp forward and make a successful step-up immediately stale.
		rec.RiskUpdatedAt = now.UTC()
	}
}

func clearStepUpRisk0126(rec *authSessionRecord, now time.Time) {
	if rec == nil {
		return
	}
	rec.RiskReasons = removeRiskReasons0126(rec.RiskReasons, "ip-changed", "user-agent-changed")
	recomputeSessionRisk0126(rec, now)
}

func (s Server) reconcileSessionDeviceRisk0126(r *http.Request, rec authSessionRecord) (authSessionRecord, error) {
	now := time.Now().UTC()
	reasons := mergeRiskReasons118(nil, rec.RiskReasons...)
	if rec.TrustedDeviceID != "" {
		device, err := s.Repo.GetTrustedDevice(rec.UserID, rec.TrustedDeviceID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				reasons = mergeRiskReasons118(reasons, "trusted-device-missing")
			} else {
				return authSessionRecord{}, err
			}
		} else if device.Status != "active" || device.TrustState != "verified" || rec.DeviceTrustState != "verified" {
			reasons = mergeRiskReasons118(reasons, "trusted-device-revoked")
		} else {
			reasons = removeRiskReasons0126(reasons, "trusted-device-missing", "trusted-device-revoked", "trusted-device-invalid")
			if device.KeyBinding == "hardware" && device.KeyAlgorithm == "p256" {
				state, _ := effectiveDeviceAttestation0124(device, now)
				if state != "verified" {
					reasons = mergeRiskReasons118(reasons, "device-attestation-stale")
				} else {
					reasons = removeRiskReasons0126(reasons, "device-attestation-stale")
				}
			} else {
				reasons = removeRiskReasons0126(reasons, "device-attestation-stale")
			}
		}
	} else {
		reasons = removeRiskReasons0126(reasons, "trusted-device-missing", "trusted-device-revoked", "trusted-device-invalid", "device-attestation-stale")
	}
	rec.RiskReasons = reasons
	recomputeSessionRisk0126(&rec, now)
	updated, err := s.State.AuthSessions.applyRisk0126(rec.ID, rec.UserID, rec.RiskState, rec.RiskScore, rec.RiskAction, rec.RiskReasons, now, rec.RiskUpdatedAt)
	if err != nil {
		return authSessionRecord{}, err
	}
	rec = updated
	if rec.RiskAction == "revoke" || rec.RiskState == "compromised" {
		s.State.AuthSessions.revoke(rec.ID, "session-risk-policy")
		_ = s.flushPersistenceState950("session-risk-revoke")
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "session-risk-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: rec.Email, Action: "auth:session:risk-revoke", Target: rec.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
		return authSessionRecord{}, errSessionRiskDenied0126
	}
	return rec, nil
}

func (s Server) writeRiskRequirement0126(w http.ResponseWriter, claims authClaims) bool {
	switch claims.RiskAction {
	case "revoke":
		writeError(w, http.StatusUnauthorized, "сессия отозвана risk policy")
		return true
	case "reattest":
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": map[string]any{
			"code":             http.StatusPreconditionRequired,
			"message":          "требуется свежая device attestation",
			"riskState":        claims.RiskState,
			"riskScore":        claims.RiskScore,
			"riskAction":       claims.RiskAction,
			"deviceId":         claims.TrustedDeviceID,
			"attestationBegin": fmt.Sprintf("POST /api/v1/auth/devices/%s/attest/begin", claims.TrustedDeviceID),
		}})
		return true
	case "step-up":
		// A sensitive operation may proceed only after phishing-resistant auth
		// performed after the risk event that triggered this decision.
		if claims.RiskUpdatedAt == 0 || claims.AuthTime < claims.RiskUpdatedAt || authStrengthLevel117(claims.AuthStrength) < authStrengthLevel117("phishing-resistant") {
			writeStepUpRequired117(w, "phishing-resistant")
			return true
		}
	}
	return false
}

func sessionRefreshProofPayload0126(refreshToken string, session authSessionRecord) string {
	return "NeverLauncher Session Device Binding v1\n" +
		"purpose=refresh\n" +
		"user=" + session.UserID + "\n" +
		"session=" + session.ID + "\n" +
		"device=" + session.TrustedDeviceID + "\n" +
		fmt.Sprintf("binding-epoch=%d\n", session.BindingEpoch) +
		"refresh-token-sha256=" + hashRefreshToken(refreshToken) + "\n"
}

func (s Server) verifyRefreshDeviceProof0126(r *http.Request, refreshToken, deviceID, signature string, session authSessionRecord) error {
	if session.TrustedDeviceID == "" {
		return nil
	}
	if session.DeviceTrustState != "verified" || strings.TrimSpace(deviceID) != session.TrustedDeviceID || strings.TrimSpace(signature) == "" {
		return errors.New("device proof required")
	}
	device, err := s.Repo.GetTrustedDevice(session.UserID, session.TrustedDeviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		return errors.New("trusted device unavailable")
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || pub.fingerprint != device.KeyFingerprint {
		return errors.New("trusted device key invalid")
	}
	if err := verifyDeviceSignature0123(pub, sessionRefreshProofPayload0126(refreshToken, session), signature); err != nil {
		return errors.New("device refresh proof invalid")
	}
	_, err = s.Repo.TouchTrustedDevice(r.Context(), session.UserID, session.TrustedDeviceID, clientIP(r), r.UserAgent())
	return err
}
