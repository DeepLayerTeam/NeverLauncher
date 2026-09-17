package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	deviceAttestationChallengeTTL0124 = 2 * time.Minute
	deviceAttestationValidity0124     = 12 * time.Hour
	deviceAttestationMethod0124       = "challenge-response-v1"
)

func effectiveDeviceAttestation0124(device model.TrustedDevice, now time.Time) (state, assurance string) {
	state = strings.ToLower(strings.TrimSpace(device.AttestationState))
	if state == "" {
		state = "unattested"
	}
	assurance = strings.ToLower(strings.TrimSpace(device.Assurance))
	if assurance == "" {
		assurance = "proof-of-possession"
	}
	if state == "verified" && (!device.AttestationExpiresAt.After(now) || device.AttestedAt.IsZero()) {
		return "expired", "proof-of-possession"
	}
	return state, assurance
}

func sanitizeAttestationFreshness0124(device model.TrustedDevice) model.TrustedDevice {
	state, assurance := effectiveDeviceAttestation0124(device, time.Now().UTC())
	device.AttestationState = state
	device.Assurance = assurance
	return device
}

func deviceAttestationPayload0124(challenge string, challengeRecord model.DeviceChallenge, device model.TrustedDevice, sessionID string, validUntil time.Time) string {
	return "NeverLauncher Device Attestation v1\n" +
		"purpose=attest\n" +
		"challenge=" + strings.TrimSpace(challenge) + "\n" +
		"user=" + strings.TrimSpace(device.UserID) + "\n" +
		"device=" + strings.TrimSpace(device.ID) + "\n" +
		"session=" + strings.TrimSpace(sessionID) + "\n" +
		"fingerprint=" + strings.TrimSpace(device.KeyFingerprint) + "\n" +
		"algorithm=" + strings.TrimSpace(device.KeyAlgorithm) + "\n" +
		"binding=" + strings.TrimSpace(device.KeyBinding) + "\n" +
		"provider=" + strings.TrimSpace(device.HardwareProvider) + "\n" +
		"issued-at=" + challengeRecord.CreatedAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"challenge-expires-at=" + challengeRecord.ExpiresAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"attestation-valid-until=" + validUntil.UTC().Format(time.RFC3339Nano) + "\n"
}

func attestationEligibleDevice0124(device model.TrustedDevice) error {
	if device.Status != "active" || device.TrustState != "verified" {
		return errors.New("device is not active")
	}
	if device.KeyBinding != "hardware" || device.KeyAlgorithm != "p256" || strings.TrimSpace(device.HardwareProvider) == "" {
		return errors.New("challenge-response attestation requires a registered hardware-bound P-256 device identity")
	}
	if strings.TrimSpace(device.PublicKey) == "" || strings.TrimSpace(device.KeyFingerprint) == "" {
		return errors.New("device key material is incomplete")
	}
	return nil
}

func sessionBoundToDevice0124(s Server, claims authClaims, deviceID string) (authSessionRecord, error) {
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok || session.Status != "active" || session.TrustedDeviceID != strings.TrimSpace(deviceID) || session.DeviceTrustState != "verified" {
		return authSessionRecord{}, errors.New("current session is not bound to this trusted device")
	}
	return session, nil
}

func (s Server) authDeviceAttestationBegin0124(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if _, err := sessionBoundToDevice0124(s, claims, deviceID); err != nil {
		writeError(w, http.StatusConflict, "текущая сессия не привязана к этому trusted device")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	if err := attestationEligibleDevice0124(device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	challengeID, err := randomToken("dta")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать attestation challenge")
		return
	}
	challenge, err := randomToken("dac")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать attestation challenge")
		return
	}
	now := time.Now().UTC()
	challengeExpires := now.Add(deviceAttestationChallengeTTL0124)
	validUntil := now.Add(deviceAttestationValidity0124)
	entry := model.DeviceChallenge{
		ID:            challengeID,
		UserID:        claims.Sub,
		DeviceID:      device.ID,
		Purpose:       "attest",
		ChallengeHash: deviceChallengeHash0121(challenge),
		Metadata: map[string]any{
			"sessionId":             claims.SessionID,
			"keyFingerprint":        device.KeyFingerprint,
			"keyAlgorithm":          device.KeyAlgorithm,
			"keyBinding":            device.KeyBinding,
			"hardwareProvider":      device.HardwareProvider,
			"attestationValidUntil": validUntil.UTC().Format(time.RFC3339Nano),
		},
		CreatedAt: now,
		ExpiresAt: challengeExpires,
	}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить attestation challenge")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": apiContractVersion,
		"data": map[string]any{
			"challengeId":             challengeID,
			"deviceId":                device.ID,
			"challenge":               challenge,
			"expiresAt":               challengeExpires,
			"attestationValidUntil":   validUntil,
			"attestationMethod":       deviceAttestationMethod0124,
			"keyFingerprint":          device.KeyFingerprint,
			"keyAlgorithm":            device.KeyAlgorithm,
			"keyBinding":              device.KeyBinding,
			"hardwareProvider":        device.HardwareProvider,
			"hardwareProvenance":      "not-remotely-verified",
			"signingPayload":          deviceAttestationPayload0124(challenge, entry, device, claims.SessionID, validUntil),
			"privateKeyServerExposed": false,
		},
	})
}

func (s Server) authDeviceAttestationComplete0124(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if _, err := sessionBoundToDevice0124(s, claims, deviceID); err != nil {
		writeError(w, http.StatusConflict, "текущая сессия не привязана к этому trusted device")
		return
	}
	var req deviceProofCompleteRequest0121
	if err := decodeDeviceJSON0121(w, r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.DeviceID != "" && strings.TrimSpace(req.DeviceID) != deviceID {
		writeError(w, http.StatusBadRequest, "deviceId не совпадает с URL")
		return
	}
	if strings.TrimSpace(req.PublicKey) != "" {
		writeError(w, http.StatusBadRequest, "attestation complete не принимает publicKey: используется уже зарегистрированный device key")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	if err := attestationEligibleDevice0124(device); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	now := time.Now().UTC()
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, deviceID, "attest", deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "attestation challenge недействителен, истёк или уже использован")
		return
	}
	if metadataString0121(ch.Metadata, "sessionId") != claims.SessionID ||
		metadataString0121(ch.Metadata, "keyFingerprint") != device.KeyFingerprint ||
		metadataString0121(ch.Metadata, "keyAlgorithm") != device.KeyAlgorithm ||
		metadataString0121(ch.Metadata, "keyBinding") != device.KeyBinding ||
		metadataString0121(ch.Metadata, "hardwareProvider") != device.HardwareProvider {
		writeError(w, http.StatusUnauthorized, "attestation challenge больше не соответствует device identity")
		return
	}
	validUntil, err := time.Parse(time.RFC3339Nano, metadataString0121(ch.Metadata, "attestationValidUntil"))
	if err != nil || !validUntil.After(now) || validUntil.After(ch.CreatedAt.Add(deviceAttestationValidity0124+time.Second)) {
		writeError(w, http.StatusUnauthorized, "attestation freshness window повреждён или истёк")
		return
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil || pub.fingerprint != device.KeyFingerprint {
		writeError(w, http.StatusInternalServerError, "device public key повреждён")
		return
	}
	payload := deviceAttestationPayload0124(req.Challenge, ch, device, claims.SessionID, validUntil)
	if err := verifyDeviceSignature0123(pub, payload, req.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	device, err = s.Repo.AttestTrustedDevice(r.Context(), claims.Sub, deviceID, deviceAttestationMethod0124, now, validUntil)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusConflict, "устройство больше не активно")
			return
		}
		writeError(w, http.StatusInternalServerError, "не удалось сохранить device attestation")
		return
	}
	device, err = s.Repo.TouchTrustedDevice(r.Context(), claims.Sub, deviceID, clientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusConflict, "устройство больше не активно")
		return
	}
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, "сессия недействительна")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "пользователь не найден")
		return
	}
	accessToken, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обновить access token")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{
		ID:        "device-attest-" + time.Now().UTC().Format("20060102150405.000000000"),
		Actor:     claims.Email,
		Action:    "auth:device:attest",
		Target:    device.ID,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		CreatedAt: now,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": apiContractVersion,
		"data": map[string]any{
			"device":                     sanitizeTrustedDevice0121(device),
			"session":                    session,
			"accessToken":                accessToken,
			"attestationState":           "verified",
			"attestationMethod":          deviceAttestationMethod0124,
			"attestedAt":                 now,
			"attestationExpiresAt":       validUntil,
			"hardwareProvenance":         "not-remotely-verified",
			"authorizationElevation":     false,
			"phishingResistantElevation": false,
		},
	})
}
