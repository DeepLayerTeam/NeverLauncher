package httpapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const deviceChallengeTTL0121 = 5 * time.Minute

type deviceRegisterBeginRequest0121 struct {
	Name             string `json:"name"`
	Platform         string `json:"platform,omitempty"`
	ClientVersion    string `json:"clientVersion,omitempty"`
	KeyAlgorithm     string `json:"keyAlgorithm,omitempty"`
	KeyBinding       string `json:"keyBinding,omitempty"`
	HardwareProvider string `json:"hardwareProvider,omitempty"`
}

type deviceProofCompleteRequest0121 struct {
	ChallengeID string `json:"challengeId"`
	DeviceID    string `json:"deviceId"`
	Challenge   string `json:"challenge"`
	PublicKey   string `json:"publicKey,omitempty"`
	Signature   string `json:"signature"`
}

type deviceRenameRequest0121 struct {
	Name string `json:"name"`
}
type adminDeviceRevokeRequest0121 struct {
	Reason string `json:"reason,omitempty"`
}

func decodeDeviceJSON0121(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("multiple JSON values")
	}
	return nil
}

func normalizeDeviceName0121(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 96 || !utf8.ValidString(v) {
		return "", errors.New("device name must contain 1-96 UTF-8 characters")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("device name contains control characters")
		}
	}
	return v, nil
}

func normalizeDeviceMetadata0121(platform, clientVersion string) (string, string, error) {
	platform = strings.TrimSpace(platform)
	clientVersion = strings.TrimSpace(clientVersion)
	if len(platform) > 48 || len(clientVersion) > 96 || !utf8.ValidString(platform) || !utf8.ValidString(clientVersion) {
		return "", "", errors.New("device platform/clientVersion is too long or invalid UTF-8")
	}
	return platform, clientVersion, nil
}

func validHardwareProvider0123(provider string) bool {
	if provider == "" || len(provider) > 96 || !utf8.ValidString(provider) {
		return false
	}
	for _, r := range provider {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func normalizeDeviceKeyProperties0123(algorithm, binding, provider string) (string, string, string, error) {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	binding = strings.ToLower(strings.TrimSpace(binding))
	provider = strings.TrimSpace(provider)
	if algorithm == "" {
		algorithm = "ed25519"
	}
	if binding == "" {
		binding = "software"
	}
	if algorithm != "ed25519" && algorithm != "p256" {
		return "", "", "", errors.New("keyAlgorithm must be ed25519 or p256")
	}
	if binding != "software" && binding != "hardware" {
		return "", "", "", errors.New("keyBinding must be software or hardware")
	}
	if binding == "hardware" {
		if algorithm != "p256" {
			return "", "", "", errors.New("hardware-bound identity requires p256")
		}
		if !validHardwareProvider0123(provider) {
			return "", "", "", errors.New("hardwareProvider is required for hardware-bound identity")
		}
	} else {
		if algorithm != "ed25519" {
			return "", "", "", errors.New("software device identity requires ed25519")
		}
		provider = ""
	}
	return algorithm, binding, provider, nil
}

type decodedDevicePublicKey0123 struct {
	algorithm   string
	raw         []byte
	ed25519Key  ed25519.PublicKey
	p256Key     *ecdsa.PublicKey
	fingerprint string
}

func decodeDevicePublicKey0123(raw, algorithm string) (decodedDevicePublicKey0123, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return decodedDevicePublicKey0123{}, errors.New("publicKey must be base64url")
	}
	out := decodedDevicePublicKey0123{algorithm: algorithm, raw: append([]byte(nil), b...)}
	switch algorithm {
	case "ed25519":
		if len(b) != ed25519.PublicKeySize {
			return decodedDevicePublicKey0123{}, errors.New("publicKey must be a raw Ed25519 public key")
		}
		out.ed25519Key = ed25519.PublicKey(b)
	case "p256":
		x, y := elliptic.Unmarshal(elliptic.P256(), b)
		if x == nil || y == nil || len(b) != 65 || b[0] != 0x04 {
			return decodedDevicePublicKey0123{}, errors.New("publicKey must be an uncompressed SEC1 P-256 public key")
		}
		out.p256Key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	default:
		return decodedDevicePublicKey0123{}, errors.New("unsupported device key algorithm")
	}
	sum := sha256.Sum256(b)
	out.fingerprint = hex.EncodeToString(sum[:])
	return out, nil
}

func verifyDeviceSignature0123(key decodedDevicePublicKey0123, payload, rawSignature string) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(rawSignature))
	if err != nil {
		return errors.New("signature must be base64url")
	}
	switch key.algorithm {
	case "ed25519":
		if len(b) != ed25519.SignatureSize || !ed25519.Verify(key.ed25519Key, []byte(payload), b) {
			return errors.New("device proof signature is invalid")
		}
	case "p256":
		if len(b) != 64 {
			return errors.New("P-256 signature must be raw IEEE P1363 r||s")
		}
		h := sha256.Sum256([]byte(payload))
		r := new(big.Int).SetBytes(b[:32])
		s := new(big.Int).SetBytes(b[32:])
		if r.Sign() <= 0 || s.Sign() <= 0 || !ecdsa.Verify(key.p256Key, h[:], r, s) {
			return errors.New("device proof signature is invalid")
		}
	default:
		return errors.New("unsupported device key algorithm")
	}
	return nil
}

func deviceChallengeHash0121(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

func deviceProofPayload0121(purpose, challenge, userID, deviceID, sessionID string) string {
	return "NeverLauncher Device Trust v1\n" +
		"purpose=" + strings.TrimSpace(purpose) + "\n" +
		"challenge=" + strings.TrimSpace(challenge) + "\n" +
		"user=" + strings.TrimSpace(userID) + "\n" +
		"device=" + strings.TrimSpace(deviceID) + "\n" +
		"session=" + strings.TrimSpace(sessionID) + "\n"
}

func metadataString0121(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func sanitizeTrustedDevice0121(d model.TrustedDevice) model.TrustedDevice {
	d.PublicKey = ""
	return d
}

func (s Server) authDevices0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	items := s.Repo.ListTrustedDevices(claims.Sub, "")
	for i := range items {
		items[i] = sanitizeTrustedDevice0121(items[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items, "count": len(items)}})
}

func (s Server) authDeviceRegisterBegin0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req deviceRegisterBeginRequest0121
	if err := decodeDeviceJSON0121(w, r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	name, err := normalizeDeviceName0121(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	platform, clientVersion, err := normalizeDeviceMetadata0121(req.Platform, req.ClientVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	keyAlgorithm, keyBinding, hardwareProvider, err := normalizeDeviceKeyProperties0123(req.KeyAlgorithm, req.KeyBinding, req.HardwareProvider)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID, err := randomToken("dev")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать device id")
		return
	}
	challengeID, err := randomToken("dtc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	challenge, err := randomToken("dch")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(deviceChallengeTTL0121)
	entry := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: deviceID, Purpose: "register", ChallengeHash: deviceChallengeHash0121(challenge), Metadata: map[string]any{"sessionId": claims.SessionID, "name": name, "platform": platform, "clientVersion": clientVersion, "keyAlgorithm": keyAlgorithm, "keyBinding": keyBinding, "hardwareProvider": hardwareProvider}, CreatedAt: now, ExpiresAt: expires}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить device challenge")
		return
	}
	payload := deviceProofPayload0121("register", challenge, claims.Sub, deviceID, claims.SessionID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"challengeId": challengeID, "deviceId": deviceID, "challenge": challenge, "expiresAt": expires, "keyAlgorithm": keyAlgorithm, "keyBinding": keyBinding, "hardwareProvider": hardwareProvider, "assurance": "proof-of-possession", "signingPayload": payload}})
}

func (s Server) authDeviceRegisterComplete0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req deviceProofCompleteRequest0121
	if err := decodeDeviceJSON0121(w, r, &req, 24<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	// The key algorithm/binding is fixed by the server-side registration challenge.
	now := time.Now().UTC()
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, req.DeviceID, "register", deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device challenge недействителен, истёк или уже использован")
		return
	}
	sessionID := metadataString0121(ch.Metadata, "sessionId")
	if sessionID == "" || sessionID != claims.SessionID {
		writeError(w, http.StatusUnauthorized, "device challenge создан для другой сессии")
		return
	}
	keyAlgorithm, keyBinding, hardwareProvider, err := normalizeDeviceKeyProperties0123(metadataString0121(ch.Metadata, "keyAlgorithm"), metadataString0121(ch.Metadata, "keyBinding"), metadataString0121(ch.Metadata, "hardwareProvider"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device challenge key properties повреждены")
		return
	}
	pub, err := decodeDevicePublicKey0123(req.PublicKey, keyAlgorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload := deviceProofPayload0121("register", req.Challenge, claims.Sub, req.DeviceID, sessionID)
	if err := verifyDeviceSignature0123(pub, payload, req.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	device := model.TrustedDevice{ID: req.DeviceID, UserID: claims.Sub, Name: metadataString0121(ch.Metadata, "name"), Status: "active", TrustState: "verified", Assurance: "proof-of-possession", KeyAlgorithm: keyAlgorithm, KeyBinding: keyBinding, HardwareProvider: hardwareProvider, PublicKey: base64.RawURLEncoding.EncodeToString(pub.raw), KeyFingerprint: pub.fingerprint, Platform: metadataString0121(ch.Metadata, "platform"), ClientVersion: metadataString0121(ch.Metadata, "clientVersion"), CreatedAt: now, UpdatedAt: now, LastSeenAt: now, LastVerifiedAt: now, LastIP: clientIP(r), LastUserAgent: r.UserAgent()}
	device, err = s.Repo.SaveTrustedDevice(r.Context(), device)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "device key уже зарегистрирован")
			return
		}
		writeError(w, http.StatusInternalServerError, "не удалось зарегистрировать устройство")
		return
	}
	device, err = s.Repo.TouchTrustedDevice(r.Context(), claims.Sub, device.ID, clientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось подтвердить устройство")
		return
	}
	session, err := s.State.AuthSessions.bindTrustedDevice121(claims.SessionID, claims.Sub, device.ID, now)
	if err != nil {
		writeError(w, http.StatusConflict, "не удалось привязать устройство к текущей сессии")
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
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-register-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:register", Target: device.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"device": sanitizeTrustedDevice0121(device), "session": session, "accessToken": accessToken}})
}

func (s Server) authDeviceVerifyBegin0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		writeError(w, http.StatusNotFound, "активное устройство не найдено")
		return
	}
	challengeID, err := randomToken("dtc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	challenge, err := randomToken("dch")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(deviceChallengeTTL0121)
	entry := model.DeviceChallenge{ID: challengeID, UserID: claims.Sub, DeviceID: device.ID, Purpose: "session-bind", ChallengeHash: deviceChallengeHash0121(challenge), Metadata: map[string]any{"sessionId": claims.SessionID}, CreatedAt: now, ExpiresAt: expires}
	if err := s.Repo.SaveDeviceChallenge(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить device challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"challengeId": challengeID, "deviceId": device.ID, "challenge": challenge, "expiresAt": expires, "keyAlgorithm": device.KeyAlgorithm, "keyBinding": device.KeyBinding, "hardwareProvider": device.HardwareProvider, "signingPayload": deviceProofPayload0121("session-bind", challenge, claims.Sub, device.ID, claims.SessionID)}})
}

func (s Server) authDeviceVerifyComplete0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	var req deviceProofCompleteRequest0121
	if err := decodeDeviceJSON0121(w, r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.DeviceID != "" && strings.TrimSpace(req.DeviceID) != deviceID {
		writeError(w, http.StatusBadRequest, "deviceId не совпадает с URL")
		return
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, deviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		writeError(w, http.StatusNotFound, "активное устройство не найдено")
		return
	}
	pub, err := decodeDevicePublicKey0123(device.PublicKey, device.KeyAlgorithm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "device public key повреждён")
		return
	}
	now := time.Now().UTC()
	ch, err := s.Repo.ConsumeDeviceChallenge(r.Context(), req.ChallengeID, claims.Sub, deviceID, "session-bind", deviceChallengeHash0121(req.Challenge), now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device challenge недействителен, истёк или уже использован")
		return
	}
	sessionID := metadataString0121(ch.Metadata, "sessionId")
	if sessionID != claims.SessionID {
		writeError(w, http.StatusUnauthorized, "device challenge создан для другой сессии")
		return
	}
	payload := deviceProofPayload0121("session-bind", req.Challenge, claims.Sub, deviceID, sessionID)
	if err := verifyDeviceSignature0123(pub, payload, req.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	device, err = s.Repo.TouchTrustedDevice(r.Context(), claims.Sub, deviceID, clientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusConflict, "устройство больше не активно")
		return
	}
	session, err := s.State.AuthSessions.bindTrustedDevice121(claims.SessionID, claims.Sub, deviceID, now)
	if err != nil {
		writeError(w, http.StatusConflict, "не удалось привязать устройство к текущей сессии")
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
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"device": sanitizeTrustedDevice0121(device), "session": session, "accessToken": accessToken}})
}

func (s Server) authDeviceRename0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req deviceRenameRequest0121
	if err := decodeDeviceJSON0121(w, r, &req, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	name, err := normalizeDeviceName0121(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	device, err := s.Repo.RenameTrustedDevice(claims.Sub, strings.TrimSpace(r.PathValue("deviceId")), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"device": sanitizeTrustedDevice0121(device)}})
}

func (s Server) authDeviceRevoke0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	device, err := s.Repo.RevokeTrustedDevice(r.Context(), claims.Sub, deviceID, "user-device-revoke")
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	revoked := s.State.AuthSessions.revokeTrustedDevice121(claims.Sub, deviceID, "device-revoked:"+deviceID)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:revoke", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"device": sanitizeTrustedDevice0121(device), "revokedSessions": revoked}})
}

func (s Server) adminAuthDevices0121(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.URL.Query().Get("userId"))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && status != "active" && status != "revoked" {
		writeError(w, http.StatusBadRequest, "status должен быть active|revoked")
		return
	}
	items := s.Repo.ListTrustedDevices(userID, status)
	for i := range items {
		items[i] = sanitizeTrustedDevice0121(items[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items, "count": len(items)}})
}

func (s Server) adminAuthDeviceRevoke0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req adminDeviceRevokeRequest0121
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	existing, err := s.Repo.GetTrustedDeviceByID(deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "admin-device-revoke"
	}
	device, err := s.Repo.RevokeTrustedDevice(r.Context(), "", deviceID, reason)
	if err != nil {
		writeError(w, http.StatusConflict, "не удалось отозвать устройство")
		return
	}
	revoked := s.State.AuthSessions.revokeTrustedDevice121(existing.UserID, deviceID, "device-revoked:"+deviceID)
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "device-admin-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:device:admin-revoke", Target: deviceID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"device": sanitizeTrustedDevice0121(device), "revokedSessions": revoked}})
}

func (s Server) authDeviceTrustStatus0121(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, "сессия недействительна")
		return
	}
	var device any
	if session.TrustedDeviceID != "" {
		if d, err := s.Repo.GetTrustedDevice(claims.Sub, session.TrustedDeviceID); err == nil {
			device = sanitizeTrustedDevice0121(d)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"sessionId": session.ID, "deviceTrustState": firstNonEmpty(session.DeviceTrustState, "unverified"), "trustedDeviceId": session.TrustedDeviceID, "deviceVerifiedAt": session.DeviceVerifiedAt, "device": device}})
}

func deviceTrustSummary0121(repo repository.Repository) map[string]any {
	items := repo.ListTrustedDevices("", "")
	active, revoked := 0, 0
	for _, d := range items {
		if d.Status == "active" {
			active++
		} else if d.Status == "revoked" {
			revoked++
		}
	}
	return map[string]any{"registered": len(items), "active": active, "revoked": revoked, "keyAlgorithm": "ed25519", "assurance": "proof-of-possession"}
}
