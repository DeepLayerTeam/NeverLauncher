package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const deviceKeyRecoveryFreshAuth0128 = 5 * time.Minute

type deviceKeyReplacementBegin0128 struct {
	OldDeviceID      string `json:"oldDeviceId,omitempty"`
	Name             string `json:"name,omitempty"`
	Platform         string `json:"platform,omitempty"`
	ClientVersion    string `json:"clientVersion,omitempty"`
	PublicKey        string `json:"publicKey"`
	KeyAlgorithm     string `json:"keyAlgorithm"`
	KeyBinding       string `json:"keyBinding"`
	HardwareProvider string `json:"hardwareProvider,omitempty"`
}

type deviceKeyReplacementComplete0128 struct {
	ChallengeID  string `json:"challengeId"`
	Challenge    string `json:"challenge"`
	OldSignature string `json:"oldSignature,omitempty"`
	NewSignature string `json:"newSignature"`
}

func deviceKeyReplacementPayload0128(mode, challenge, userID, sessionID, oldDeviceID, oldFingerprint, newDeviceID, newFingerprint, algorithm, binding, provider string, issuedAt, expiresAt time.Time) string {
	return "NeverLauncher Device Key Replacement v1\n" +
		"purpose=" + strings.TrimSpace(mode) + "\n" +
		"challenge=" + strings.TrimSpace(challenge) + "\n" +
		"user=" + strings.TrimSpace(userID) + "\n" +
		"session=" + strings.TrimSpace(sessionID) + "\n" +
		"old-device=" + strings.TrimSpace(oldDeviceID) + "\n" +
		"old-fingerprint=" + strings.TrimSpace(oldFingerprint) + "\n" +
		"new-device=" + strings.TrimSpace(newDeviceID) + "\n" +
		"new-fingerprint=" + strings.TrimSpace(newFingerprint) + "\n" +
		"new-algorithm=" + strings.TrimSpace(algorithm) + "\n" +
		"new-binding=" + strings.TrimSpace(binding) + "\n" +
		"new-provider=" + strings.TrimSpace(provider) + "\n" +
		"issued-at=" + issuedAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"expires-at=" + expiresAt.UTC().Format(time.RFC3339Nano) + "\n"
}

func (s Server) authDeviceKeyRotateBegin0128(w http.ResponseWriter, r *http.Request) {
	s.authDeviceKeyReplacementBegin0128(w, r, "rotate")
}
func (s Server) authDeviceKeyRecoverBegin0128(w http.ResponseWriter, r *http.Request) {
	s.authDeviceKeyReplacementBegin0128(w, r, "recover")
}
func (s Server) authDeviceKeyRotateComplete0128(w http.ResponseWriter, r *http.Request) {
	s.authDeviceKeyReplacementComplete0128(w, r, "rotate")
}
func (s Server) authDeviceKeyRecoverComplete0128(w http.ResponseWriter, r *http.Request) {
	s.authDeviceKeyReplacementComplete0128(w, r, "recover")
}

func (s Server) authDeviceKeyReplacementBegin0128(w http.ResponseWriter, r *http.Request, mode string) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if mode == "recover" && !freshAuth117(claims, "phishing-resistant", deviceKeyRecoveryFreshAuth0128) {
		writeStepUpRequired117(w, "phishing-resistant")
		return
	}
	var req deviceKeyReplacementBegin0128
	if err := decodeDeviceJSON0121(w, r, &req, 24<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	platform, clientVersion, err := normalizeDeviceMetadata0121(req.Platform, req.ClientVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	algorithm, binding, provider, err := normalizeDeviceKeyProperties0123(req.KeyAlgorithm, req.KeyBinding, req.HardwareProvider)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	newPub, err := decodeDevicePublicKey0123(req.PublicKey, algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, "сессия недействительна")
		return
	}
	oldDeviceID := strings.TrimSpace(req.OldDeviceID)
	if mode == "rotate" {
		oldDeviceID = strings.TrimSpace(session.TrustedDeviceID)
		if oldDeviceID == "" || session.DeviceTrustState != "verified" {
			writeError(w, http.StatusConflict, "rotation требует текущую verified device binding")
			return
		}
	} else if oldDeviceID == "" {
		oldDeviceID = strings.TrimSpace(session.TrustedDeviceID)
	}
	if oldDeviceID == "" {
		writeError(w, http.StatusBadRequest, "oldDeviceId обязателен для recovery")
		return
	}
	oldDevice, err := s.Repo.GetTrustedDevice(claims.Sub, oldDeviceID)
	if err != nil || oldDevice.Status != "active" || oldDevice.TrustState != "verified" {
		writeError(w, http.StatusNotFound, "активное исходное устройство не найдено")
		return
	}
	if mode == "rotate" && oldDevice.ID != session.TrustedDeviceID {
		writeError(w, http.StatusConflict, "rotation разрешён только для device текущей сессии")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = oldDevice.Name
	}
	name, err = normalizeDeviceName0121(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if platform == "" {
		platform = oldDevice.Platform
	}
	if clientVersion == "" {
		clientVersion = oldDevice.ClientVersion
	}

	newDeviceID, err := randomToken("dev")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать replacement device id")
		return
	}
	challengeID, err := randomToken("dkr")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	challenge, err := randomToken("dkc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(deviceChallengeTTL0121)
	purpose := "key-" + mode
	entry := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: oldDevice.ID, Purpose: purpose, ChallengeHash: deviceChallengeHash0121(challenge), CreatedAt: now, ExpiresAt: expires, Metadata: map[string]any{
		"sessionId": claims.SessionID, "newDeviceId": newDeviceID, "newPublicKey": strings.TrimSpace(req.PublicKey), "newFingerprint": newPub.fingerprint,
		"keyAlgorithm": algorithm, "keyBinding": binding, "hardwareProvider": provider, "name": name, "platform": platform, "clientVersion": clientVersion,
		"oldFingerprint": oldDevice.KeyFingerprint, "issuedAt": now.Format(time.RFC3339Nano), "expiresAt": expires.Format(time.RFC3339Nano),
	}}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить replacement challenge")
		return
	}
	payload := deviceKeyReplacementPayload0128(mode, challenge, claims.Sub, claims.SessionID, oldDevice.ID, oldDevice.KeyFingerprint, newDeviceID, newPub.fingerprint, algorithm, binding, provider, now, expires)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"mode": mode, "challengeId": challengeID, "challenge": challenge, "expiresAt": expires, "oldDeviceId": oldDevice.ID, "newDeviceId": newDeviceID,
		"newFingerprint": newPub.fingerprint, "keyAlgorithm": algorithm, "keyBinding": binding, "hardwareProvider": provider, "signingPayload": payload,
		"oldKeyProofRequired": mode == "rotate", "freshPhishingResistantAuthRequired": mode == "recover",
	}})
}

func (s Server) authDeviceKeyReplacementComplete0128(w http.ResponseWriter, r *http.Request, mode string) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if mode == "recover" && !freshAuth117(claims, "phishing-resistant", deviceKeyRecoveryFreshAuth0128) {
		writeStepUpRequired117(w, "phishing-resistant")
		return
	}
	var req deviceKeyReplacementComplete0128
	if err := decodeDeviceJSON0121(w, r, &req, 24<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	oldDeviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if oldDeviceID == "" {
		writeError(w, http.StatusBadRequest, "deviceId обязателен")
		return
	}
	oldDevice, err := s.Repo.GetTrustedDevice(claims.Sub, oldDeviceID)
	if err != nil || oldDevice.Status != "active" || oldDevice.TrustState != "verified" {
		writeError(w, http.StatusNotFound, "активное исходное устройство не найдено")
		return
	}
	now := time.Now().UTC()
	purpose := "key-" + mode
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, oldDeviceID, purpose, deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "replacement challenge недействителен, истёк или уже использован")
		return
	}
	if metadataString0121(ch.Metadata, "sessionId") != claims.SessionID {
		writeError(w, http.StatusUnauthorized, "replacement challenge создан для другой сессии")
		return
	}
	issuedAt, err1 := time.Parse(time.RFC3339Nano, metadataString0121(ch.Metadata, "issuedAt"))
	expiresAt, err2 := time.Parse(time.RFC3339Nano, metadataString0121(ch.Metadata, "expiresAt"))
	if err1 != nil || err2 != nil || !expiresAt.After(now) {
		writeError(w, http.StatusUnauthorized, "replacement challenge freshness повреждена")
		return
	}
	newDeviceID := metadataString0121(ch.Metadata, "newDeviceId")
	newPublicKey := metadataString0121(ch.Metadata, "newPublicKey")
	algorithm := metadataString0121(ch.Metadata, "keyAlgorithm")
	binding := metadataString0121(ch.Metadata, "keyBinding")
	provider := metadataString0121(ch.Metadata, "hardwareProvider")
	newFingerprint := metadataString0121(ch.Metadata, "newFingerprint")
	oldFingerprint := metadataString0121(ch.Metadata, "oldFingerprint")
	payload := deviceKeyReplacementPayload0128(mode, req.Challenge, claims.Sub, claims.SessionID, oldDeviceID, oldFingerprint, newDeviceID, newFingerprint, algorithm, binding, provider, issuedAt, expiresAt)
	newPub, err := decodeDevicePublicKey0123(newPublicKey, algorithm)
	if err != nil || newPub.fingerprint != newFingerprint {
		writeError(w, http.StatusInternalServerError, "replacement public key metadata повреждена")
		return
	}
	if err := verifyDeviceSignature0123(newPub, payload, req.NewSignature); err != nil {
		writeError(w, http.StatusUnauthorized, "новый device key не подтвердил владение")
		return
	}
	if mode == "rotate" {
		oldPub, err := decodeDevicePublicKey0123(oldDevice.PublicKey, oldDevice.KeyAlgorithm)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "исходный device public key повреждён")
			return
		}
		if err := verifyDeviceSignature0123(oldPub, payload, req.OldSignature); err != nil {
			writeError(w, http.StatusUnauthorized, "исходный device key не подтвердил rotation")
			return
		}
		session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
		if !ok || session.TrustedDeviceID != oldDeviceID || session.DeviceTrustState != "verified" {
			writeError(w, http.StatusConflict, "текущая session больше не привязана к исходному device")
			return
		}
	}

	replacement := model.TrustedDevice{ID: newDeviceID, UserID: claims.Sub, Name: metadataString0121(ch.Metadata, "name"), Status: "active", TrustState: "verified", Assurance: "proof-of-possession", KeyAlgorithm: algorithm, KeyBinding: binding, HardwareProvider: provider, AttestationState: "unattested", PublicKey: newPublicKey, KeyFingerprint: newFingerprint, Platform: metadataString0121(ch.Metadata, "platform"), ClientVersion: metadataString0121(ch.Metadata, "clientVersion"), CreatedAt: now, UpdatedAt: now, LastSeenAt: now, LastVerifiedAt: now, LastIP: clientIP(r), LastUserAgent: r.UserAgent()}
	reason := "device-key-" + mode
	var result model.DeviceKeyReplacementResult
	if atomicRepo, ok := s.Repo.(repository.DeviceKeyReplacementRepository); ok {
		result, err = atomicRepo.ReplaceTrustedDeviceKey(r.Context(), claims.Sub, oldDeviceID, claims.SessionID, mode, reason, replacement, now)
		if err != nil {
			writeError(w, http.StatusConflict, "не удалось атомарно заменить device key")
			return
		}
	} else {
		// In-memory/dev fallback preserves the same ordering: replacement first,
		// current-session rebind second, old identity revoke last. On any failure
		// before rebind the replacement is revoked so it cannot become an orphaned
		// active identity.
		replacement, err = s.Repo.SaveTrustedDevice(r.Context(), replacement)
		if err != nil {
			if errors.Is(err, repository.ErrConflict) {
				writeError(w, http.StatusConflict, "replacement device key уже зарегистрирован")
			} else {
				writeError(w, http.StatusInternalServerError, "не удалось сохранить replacement device")
			}
			return
		}
		if _, err = s.State.AuthSessions.bindTrustedDevice121(claims.SessionID, claims.Sub, replacement.ID, now); err != nil {
			_, _ = s.Repo.RevokeTrustedDevice(r.Context(), claims.Sub, replacement.ID, "replacement-bind-failed")
			writeError(w, http.StatusConflict, "не удалось перепривязать session к replacement device")
			return
		}
		oldDevice.ReplacedAt = now
		oldDevice.ReplacedByDeviceID = replacement.ID
		oldDevice.ReplacementReason = mode
		_, _ = s.Repo.SaveTrustedDevice(r.Context(), oldDevice)
		rev, revokeErr := s.Repo.RevokeTrustedDevice(r.Context(), claims.Sub, oldDeviceID, reason)
		if revokeErr != nil {
			writeError(w, http.StatusInternalServerError, "replacement создан, но revoke исходного device завершился ошибкой")
			return
		}
		applyDeviceRevocationCascade0125(s, claims.Sub, oldDeviceID, reason, &rev)
		result = model.DeviceKeyReplacementResult{OldDevice: rev.Device, NewDevice: replacement, RevokedSessions: rev.RevokedSessions, RevokedRefreshFamilies: rev.RevokedRefreshFamilies, RevokedMinecraftSessions: rev.RevokedMinecraftSessions, InvalidatedChallenges: rev.InvalidatedChallenges, RevokedSessionIDs: rev.RevokedSessionIDs}
		if minecraftRepo, ok := s.Repo.(repository.MinecraftRepository); ok {
			result.RevokedMinecraftSessions += minecraftRepo.RevokeMinecraftSessionsByNeverSession(claims.SessionID, reason)
		}
	}

	// ServerBridge lives outside PostgreSQL, so invalidate joins for both the
	// rebound current session and every revoked sibling session after commit.
	invalidatedBridge := s.State.ServerBridge.invalidateSession(claims.SessionID, "")
	seen := map[string]struct{}{claims.SessionID: {}}
	for _, sid := range result.RevokedSessionIDs {
		if _, ok := seen[sid]; ok {
			continue
		}
		seen[sid] = struct{}{}
		invalidatedBridge += s.State.ServerBridge.invalidateSession(sid, "")
	}
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok || session.TrustedDeviceID != newDeviceID {
		writeError(w, http.StatusInternalServerError, "replacement committed, but rebound session cannot be loaded")
		return
	}
	session, err = s.reconcileSessionDeviceRisk0126(r, session)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "replacement завершён, но session отозвана risk policy")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "пользователь не найден")
		return
	}
	access, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить access token после replacement")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-key-" + mode + "-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:key-" + mode, Target: oldDeviceID + "->" + newDeviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"mode": mode, "oldDevice": sanitizeTrustedDevice0121(result.OldDevice), "device": sanitizeTrustedDevice0121(result.NewDevice), "session": session, "accessToken": access,
		"revokedSessions": result.RevokedSessions, "revokedRefreshFamilies": result.RevokedRefreshFamilies, "revokedMinecraftSessions": result.RevokedMinecraftSessions, "invalidatedChallenges": result.InvalidatedChallenges, "invalidatedBridgeJoins": invalidatedBridge,
		"oldFingerprintPermanentTombstone": true, "newAttestationRequired": binding == "hardware",
	}})
}
