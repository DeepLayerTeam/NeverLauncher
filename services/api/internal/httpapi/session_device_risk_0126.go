package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

var errSessionRiskDenied0126 = errors.New("session risk policy denied request")
var errSessionBindingChanged0432 = errors.New("device session binding changed during authenticated operation")

func sameDeviceBinding0432(current, expected authSessionRecord) bool {
	return current.ID == expected.ID && current.UserID == expected.UserID &&
		current.TrustedDeviceID == expected.TrustedDeviceID &&
		current.DeviceTrustState == expected.DeviceTrustState &&
		current.BindingEpoch == expected.BindingEpoch
}

func sessionBindingClaimsMatch0126(claims authClaims, session authSessionRecord) bool {
	epoch := session.BindingEpoch
	if epoch < 1 {
		epoch = 1
	}
	// Совместимость с токеном доступа, выданным 0.12.5 непосредственно перед
	// обновлением бэкенда на месте. Следующая привязка увеличит эпоху, поэтому
	// старые и допривязочные токены не смогут использовать этот путь.
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
	hwidChanged := false
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
		case "hwid-signal-changed":
			hwidChanged = true
		case "device-attestation-stale":
			score += 40
			reattest = true
		case "trusted-device-revoked", "trusted-device-missing", "trusted-device-invalid", "refresh-token-reuse":
			score = 100
			compromise = true
		default:
			// Неизвестные сохранённые причины безопасности не понижаются молча.
			score += 25
			network = true
		}
	}
	// HWID may request a step-up but must never independently turn a session
	// into a compromised/ban decision or push another weak signal over 100.
	if hwidChanged && !compromise {
		network = true
		if score < 100 {
			score += 20
			if score >= 100 {
				score = 99
			}
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case compromise || score >= 100:
		return "compromised", 100, "revoke"
	case reattest:
		// Актуальность ключа устройства нельзя подтвердить только MFA учётной записи. Если
		// доступны оба сигнала, предпочитайте повторную аттестацию сетевому step-up.
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
		// RiskUpdatedAt — момент изменения решения, а не очередной
		// оценки. Иначе каждый чувствительный запрос сдвигал бы
		// отметку и сразу делал успешный step-up устаревшим.
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
			// Optional HWID observation is not attestation. Storage failure
			// does not trigger mass revocation or an automatic ban.
			if store, ok := s.Repo.(repository.HWIDStore0299); ok {
				observation, hwidErr := store.GetHWID0299(r.Context(), rec.UserID, rec.TrustedDeviceID, now)
				if hwidErr == nil && observation.State == "changed" {
					reasons = mergeRiskReasons118(reasons, "hwid-signal-changed")
				} else {
					reasons = removeRiskReasons0126(reasons, "hwid-signal-changed")
				}
			}
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
		reasons = removeRiskReasons0126(reasons, "trusted-device-missing", "trusted-device-revoked", "trusted-device-invalid", "device-attestation-stale", "hwid-signal-changed")
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
		ip, userAgent := "", ""
		if r != nil {
			ip = clientIP(r)
			userAgent = r.UserAgent()
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "session-risk-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: rec.Email, Action: "auth:session:risk-revoke", Target: rec.ID, IP: ip, UserAgent: userAgent, CreatedAt: now})
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
		// Чувствительную операцию разрешайте только после устойчивой к фишингу
		// аутентификации, выполненной позже события риска, вызвавшего решение.
		if claims.RiskUpdatedAt == 0 || claims.AuthTime < claims.RiskUpdatedAt || authStrengthLevel117(claims.AuthStrength) < authStrengthLevel117("phishing-resistant") {
			writeStepUpRequired117(w, "phishing-resistant")
			return true
		}
	}
	return false
}

func sessionRefreshProofPayload0126(refreshToken string, session authSessionRecord) string {
	return "Launcher Session Device Binding v1\n" +
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
