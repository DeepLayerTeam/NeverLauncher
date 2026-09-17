package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	wa "gitflic.ru/skif4er/neverlauncher/services/api/internal/webauthn"
)

type webauthnRegistrationComplete117 struct {
	TransactionToken string                      `json:"transactionToken"`
	FriendlyName     string                      `json:"friendlyName,omitempty"`
	Credential       webauthnRegistrationJSON117 `json:"credential"`
}
type webauthnRegistrationJSON117 struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		Transports        []string `json:"transports,omitempty"`
	} `json:"response"`
}
type webauthnAssertionComplete117 struct {
	TransactionToken string                   `json:"transactionToken"`
	DeviceID         string                   `json:"deviceId,omitempty"`
	Credential       webauthnAssertionJSON117 `json:"credential"`
}
type webauthnAssertionJSON117 struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response"`
}
type passkeyRename117 struct {
	FriendlyName string `json:"friendlyName"`
}
type mfaPolicyWrite117 struct {
	Requirement string `json:"requirement"`
}
type mfaStepUpTOTP117 struct {
	TOTP         string `json:"totp,omitempty"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
}

func (s Server) authPasskeys117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	items := s.State.Passkeys.listByUser(claims.Sub)
	out := make([]map[string]any, 0, len(items))
	for _, c := range items {
		out = append(out, c.public())
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": out, "policy": s.State.Passkeys.policy(claims.Sub), "rpId": s.Config.WebAuthnRPID}})
}

func (s Server) authPasskeyRegisterBegin117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !freshAuth117(claims, "single-factor", 5*time.Minute) {
		writeStepUpRequired117(w, "single-factor")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, "пользователь недоступен")
		return
	}
	challenge, err := newChallengeBytes117()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать WebAuthn challenge")
		return
	}
	token, err := s.State.Passkeys.createChallenge(user.ID, "passkey-register", challenge, map[string]any{"sessionId": claims.SessionID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить WebAuthn challenge")
		return
	}
	exclude := make([]map[string]any, 0)
	for _, c := range s.State.Passkeys.listByUser(user.ID) {
		exclude = append(exclude, map[string]any{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(c.CredentialID), "transports": c.Transports})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"transactionToken": token, "expiresInSeconds": int(webauthnChallengeTTL117.Seconds()), "publicKey": map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge), "rp": map[string]any{"id": s.Config.WebAuthnRPID, "name": firstNonEmpty(s.Config.WebAuthnRPName, "NeverLauncher")}, "user": map[string]any{"id": base64.RawURLEncoding.EncodeToString(s.webauthnUserHandle117(user.ID)), "name": user.Email, "displayName": firstNonEmpty(user.DisplayName, user.Email)}, "pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -257}}, "timeout": int(webauthnChallengeTTL117.Milliseconds()), "excludeCredentials": exclude, "authenticatorSelection": map[string]any{"residentKey": "required", "requireResidentKey": true, "userVerification": "required"}, "attestation": "none"}}})
}

func (s Server) authPasskeyRegisterComplete117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req webauthnRegistrationComplete117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный WebAuthn JSON")
		return
	}
	tx, err := s.State.Passkeys.consumeChallenge(req.TransactionToken, "passkey-register")
	if err != nil || tx.UserID != claims.Sub || metadataString117(tx.Metadata, "sessionId") != claims.SessionID {
		writeError(w, http.StatusUnauthorized, "WebAuthn transaction недействительна или истекла")
		return
	}
	rawID, clientData, attObj, err := decodeRegistrationCredential117(req.Credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := wa.VerifyRegistration(s.webauthnVerifyConfig117(tx.Challenge), clientData, attObj, rawID)
	if err != nil {
		s.audit(r, claims.Email, "auth:passkey:registration-failed", err.Error())
		writeError(w, http.StatusUnauthorized, "WebAuthn registration verification failed")
		return
	}
	name, err := validateFriendlyName117(req.FriendlyName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := randomToken("pkc")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать credential id")
		return
	}
	credential := passkeyCredential117{ID: id, UserID: claims.Sub, CredentialID: result.CredentialID, UserHandle: s.webauthnUserHandle117(claims.Sub), PublicKeyCOSE: result.PublicKeyCOSE, Algorithm: result.Algorithm, SignCount: result.SignCount, AAGUID: result.AAGUID, Transports: normalizeTransports117(req.Credential.Response.Transports), FriendlyName: name, BackupEligible: result.BackupEligible, BackedUp: result.BackedUp, Status: "active"}
	if err := s.State.Passkeys.saveCredential(credential); err != nil {
		writeError(w, http.StatusConflict, "passkey уже зарегистрирован")
		return
	}
	// Registration itself is a fresh UV ceremony, so the current session is stepped up.
	session, err := s.State.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "сессия больше не активна")
		return
	}
	user, _ := s.Repo.GetUser(claims.Sub)
	access, _ := s.issueAccessTokenForSession(user, session)
	s.audit(r, claims.Email, "auth:passkey:registered", credential.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "registered", "credential": credential.public(), "session": sanitizeSessionRecord(session), "accessToken": access}})
}

func (s Server) authPasskeyLoginBegin117(w http.ResponseWriter, r *http.Request) {
	challenge, err := newChallengeBytes117()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать WebAuthn challenge")
		return
	}
	token, err := s.State.Passkeys.createChallenge("", "passkey-login", challenge, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить WebAuthn challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"transactionToken": token, "expiresInSeconds": int(webauthnChallengeTTL117.Seconds()), "publicKey": s.passkeyAssertionOptions117(challenge, "")}})
}

func (s Server) authPasskeyLoginComplete117(w http.ResponseWriter, r *http.Request) {
	var req webauthnAssertionComplete117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный WebAuthn JSON")
		return
	}
	tx, err := s.State.Passkeys.consumeChallenge(req.TransactionToken, "passkey-login")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "WebAuthn transaction недействительна или истекла")
		return
	}
	credential, result, err := s.verifyPasskeyAssertion117(req.Credential, tx.Challenge, "")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	user, err := s.Repo.GetUser(credential.UserID)
	if err != nil || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, "пользователь недоступен")
		return
	}
	if err := s.State.Passkeys.updateUse(credential.ID, user.ID, result.SignCount, result.BackedUp); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обновить passkey state")
		return
	}
	s.issuePasskeyLogin117(w, r, user, firstNonEmpty(req.DeviceID, "passkey-client"), "passkey", "", nil)
}

func (s Server) authPasskeyMFALoginComplete117(w http.ResponseWriter, r *http.Request) {
	var req webauthnAssertionComplete117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный WebAuthn JSON")
		return
	}
	tx, err := s.State.Passkeys.consumeChallenge(req.TransactionToken, "passkey-mfa-login")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "MFA transaction недействительна или истекла")
		return
	}
	credential, result, err := s.verifyPasskeyAssertion117(req.Credential, tx.Challenge, tx.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "passkey MFA verification failed")
		return
	}
	user, err := s.Repo.GetUser(tx.UserID)
	if err != nil || user.Status == "disabled" || credential.UserID != user.ID {
		writeError(w, http.StatusUnauthorized, "пользователь недоступен")
		return
	}
	if err := s.State.Passkeys.updateUse(credential.ID, user.ID, result.SignCount, result.BackedUp); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обновить passkey state")
		return
	}
	methods := metadataStrings117(tx.Metadata, "authMethods")
	provider := metadataString117(tx.Metadata, "provider")
	identityID := metadataString117(tx.Metadata, "identityId")
	device := firstNonEmpty(req.DeviceID, metadataString117(tx.Metadata, "deviceId"), "desktop-client")
	s.issuePasskeyLogin117(w, r, user, device, provider, identityID, methods)
}

func (s Server) authPasskeyStepUpBegin117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if s.State.Passkeys.countByUser(claims.Sub) == 0 {
		writeError(w, http.StatusBadRequest, "у пользователя нет активных passkeys")
		return
	}
	challenge, err := newChallengeBytes117()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать challenge")
		return
	}
	token, err := s.State.Passkeys.createChallenge(claims.Sub, "passkey-step-up", challenge, map[string]any{"sessionId": claims.SessionID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"transactionToken": token, "publicKey": s.passkeyAssertionOptions117(challenge, claims.Sub), "expiresInSeconds": int(webauthnChallengeTTL117.Seconds())}})
}

func (s Server) authPasskeyStepUpComplete117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req webauthnAssertionComplete117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный WebAuthn JSON")
		return
	}
	tx, err := s.State.Passkeys.consumeChallenge(req.TransactionToken, "passkey-step-up")
	if err != nil || tx.UserID != claims.Sub || metadataString117(tx.Metadata, "sessionId") != claims.SessionID {
		writeError(w, http.StatusUnauthorized, "step-up transaction недействительна")
		return
	}
	credential, result, err := s.verifyPasskeyAssertion117(req.Credential, tx.Challenge, claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "passkey step-up verification failed")
		return
	}
	if err := s.State.Passkeys.updateUse(credential.ID, claims.Sub, result.SignCount, result.BackedUp); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось обновить passkey state")
		return
	}
	session, err := s.State.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{"passkey", "user-verification"}, "phishing-resistant", time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "сессия не активна")
		return
	}
	user, _ := s.Repo.GetUser(claims.Sub)
	access, err := s.issueAccessTokenForSession(user, session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить access token")
		return
	}
	s.audit(r, claims.Email, "auth:step-up:passkey", claims.SessionID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "stepped-up", "session": sanitizeSessionRecord(session), "accessToken": access, "accessTokenTtlMinutes": int(accessTokenTTL.Minutes())}})
}

func (s Server) authMFAStepUpTOTP117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req mfaStepUpTOTP117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	ok, reason := s.State.Security.verifySecondFactor(claims.Sub, req.TOTP, req.RecoveryCode)
	if !ok || reason == "mfa-not-enabled" {
		writeError(w, http.StatusUnauthorized, "требуется действительный TOTP или recovery code")
		return
	}
	method := "totp"
	if reason == "recovery-ok" {
		method = "recovery-code"
	}
	session, err := s.State.AuthSessions.stepUp(claims.SessionID, claims.Sub, []string{method}, "mfa", time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "сессия не активна")
		return
	}
	user, _ := s.Repo.GetUser(claims.Sub)
	access, _ := s.issueAccessTokenForSession(user, session)
	s.audit(r, claims.Email, "auth:step-up:"+method, claims.SessionID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "stepped-up", "session": sanitizeSessionRecord(session), "accessToken": access}})
}

func (s Server) authPasskeyRename117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req passkeyRename117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	name, err := validateFriendlyName117(req.FriendlyName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.State.Passkeys.rename(r.PathValue("credentialId"), claims.Sub, name); err != nil {
		writeError(w, http.StatusNotFound, "passkey не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "renamed"}})
}
func (s Server) authPasskeyDelete117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !freshAuth117(claims, "phishing-resistant", 5*time.Minute) {
		writeStepUpRequired117(w, "phishing-resistant")
		return
	}
	policy := s.State.Passkeys.policy(claims.Sub)
	if s.State.Passkeys.countByUser(claims.Sub) <= 1 && (policy == mfaPhishingResistant117 || (policy == mfaRequired117 && !s.State.Security.totpEnabled(claims.Sub))) {
		writeError(w, http.StatusConflict, "сначала снизьте MFA policy или добавьте другой активный MFA method")
		return
	}
	if err := s.State.Passkeys.revoke(r.PathValue("credentialId"), claims.Sub); err != nil {
		writeError(w, http.StatusNotFound, "passkey не найден")
		return
	}
	s.audit(r, claims.Email, "auth:passkey:revoked", r.PathValue("credentialId"))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "revoked"}})
}

func (s Server) authMFAStatus117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"requirement": s.State.Passkeys.policy(claims.Sub), "methods": map[string]any{"totp": s.State.Security.totpEnabled(claims.Sub), "passkeys": s.State.Passkeys.countByUser(claims.Sub), "recoveryCodes": "single-use"}, "session": map[string]any{"authStrength": claims.AuthStrength, "authMethods": claims.AuthMethods, "authTime": time.Unix(claims.AuthTime, 0).UTC()}}})
}
func (s Server) authMFAPolicy117(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req mfaPolicyWrite117
	if err := decodeJSONLimited117(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	target := normalizeMFARequirement117(req.Requirement)
	if target == "" {
		writeError(w, http.StatusBadRequest, "requirement должен быть optional|required|phishing-resistant")
		return
	}
	current := s.State.Passkeys.policy(claims.Sub)
	requiredStrength := "single-factor"
	if target == mfaRequired117 {
		requiredStrength = "mfa"
	}
	if target == mfaPhishingResistant117 {
		requiredStrength = "phishing-resistant"
	}
	if authStrengthLevel117(currentRequirementStrength117(current)) > authStrengthLevel117(requiredStrength) {
		requiredStrength = currentRequirementStrength117(current)
	}
	if requiredStrength != "single-factor" && !freshAuth117(claims, requiredStrength, 5*time.Minute) {
		writeStepUpRequired117(w, requiredStrength)
		return
	}
	if target == mfaRequired117 && !s.State.Security.totpEnabled(claims.Sub) && s.State.Passkeys.countByUser(claims.Sub) == 0 {
		writeError(w, http.StatusConflict, "для REQUIRED сначала включите TOTP или зарегистрируйте passkey")
		return
	}
	if target == mfaPhishingResistant117 && s.State.Passkeys.countByUser(claims.Sub) == 0 {
		writeError(w, http.StatusConflict, "для PHISHING_RESISTANT сначала зарегистрируйте passkey")
		return
	}
	if err := s.State.Passkeys.setPolicy(claims.Sub, target); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить MFA policy")
		return
	}
	s.audit(r, claims.Email, "auth:mfa:policy", target)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"requirement": target, "previous": current}})
}

func (s Server) issuePasskeyLogin117(w http.ResponseWriter, r *http.Request, user model.User, deviceID, provider, identityID string, baseMethods []string) {
	methods := mergeAuthMethods117(baseMethods, "passkey", "user-verification")
	access, refresh, session, err := s.issueLoginSessionWithAuth(user, r, deviceID, methods, "phishing-resistant", time.Now().UTC(), identityID, firstNonEmpty(provider, "passkey"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать серверную сессию")
		return
	}
	if updated, err := s.Repo.TouchUserLogin(user.ID); err == nil {
		user = updated
	}
	s.State.Security.recordLoginSuccess("passkey:"+user.ID, clientIP(r))
	s.audit(r, user.Email, "auth:passkey:login", session.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "authenticated", "authMethods": methods, "authStrength": "phishing-resistant", "user": sanitizeUserAccount(user), "session": sanitizeSessionRecord(session), "tokens": map[string]any{"accessToken": access, "accessTokenTtlMinutes": int(accessTokenTTL.Minutes()), "refreshToken": refresh, "refreshTokenTtlDays": int(refreshTokenTTL.Hours() / 24), "rotation": true}}})
}

func (s Server) startPasskeyMFAContinuation117(user model.User, provider, identityID, deviceID string, methods []string) (map[string]any, error) {
	if s.State.Passkeys.countByUser(user.ID) == 0 {
		return nil, errors.New("MFA policy requires passkey but no passkey is registered")
	}
	challenge, err := newChallengeBytes117()
	if err != nil {
		return nil, err
	}
	token, err := s.State.Passkeys.createChallenge(user.ID, "passkey-mfa-login", challenge, map[string]any{"provider": provider, "identityId": identityID, "deviceId": deviceID, "authMethods": methods})
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "mfa-required", "requirement": "phishing-resistant", "method": "passkey", "transactionToken": token, "expiresInSeconds": int(webauthnChallengeTTL117.Seconds()), "publicKey": s.passkeyAssertionOptions117(challenge, user.ID)}, nil
}

func (s Server) verifyPasskeyAssertion117(input webauthnAssertionJSON117, challenge []byte, expectedUser string) (passkeyCredential117, wa.AssertionResult, error) {
	raw, client, authData, sig, userHandle, err := decodeAssertionCredential117(input)
	if err != nil {
		return passkeyCredential117{}, wa.AssertionResult{}, err
	}
	credential, err := s.State.Passkeys.credentialByRawID(raw)
	if err != nil {
		return passkeyCredential117{}, wa.AssertionResult{}, err
	}
	if expectedUser != "" && credential.UserID != expectedUser {
		return passkeyCredential117{}, wa.AssertionResult{}, errors.New("passkey user mismatch")
	}
	if len(userHandle) > 0 && !hmac.Equal(userHandle, s.webauthnUserHandle117(credential.UserID)) {
		return passkeyCredential117{}, wa.AssertionResult{}, errors.New("userHandle mismatch")
	}
	result, err := wa.VerifyAssertion(s.webauthnVerifyConfig117(challenge), client, authData, sig, credential.PublicKeyCOSE, credential.SignCount, credential.BackupEligible)
	return credential, result, err
}
func (s Server) webauthnVerifyConfig117(challenge []byte) wa.VerifyConfig {
	origins := map[string]struct{}{}
	for _, o := range s.Config.WebAuthnOrigins {
		if v := strings.TrimSpace(o); v != "" {
			origins[v] = struct{}{}
		}
	}
	if len(origins) == 0 {
		origins[strings.TrimRight(s.Config.PublicURL, "/")] = struct{}{}
	}
	return wa.VerifyConfig{RPID: firstNonEmpty(s.Config.WebAuthnRPID, "localhost"), Origins: origins, Challenge: challenge, RequireUV: true}
}
func (s Server) webauthnUserHandle117(userID string) []byte {
	mac := hmac.New(sha256.New, []byte(s.Config.AuthTokenSecret))
	mac.Write([]byte("neverlauncher/webauthn-user/v1\x00"))
	mac.Write([]byte(userID))
	return mac.Sum(nil)
}
func (s Server) passkeyAssertionOptions117(challenge []byte, userID string) map[string]any {
	allow := []map[string]any{}
	if userID != "" {
		for _, c := range s.State.Passkeys.listByUser(userID) {
			allow = append(allow, map[string]any{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(c.CredentialID), "transports": c.Transports})
		}
	}
	out := map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(challenge), "rpId": firstNonEmpty(s.Config.WebAuthnRPID, "localhost"), "timeout": int(webauthnChallengeTTL117.Milliseconds()), "userVerification": "required"}
	if len(allow) > 0 {
		out["allowCredentials"] = allow
	}
	return out
}

func decodeRegistrationCredential117(c webauthnRegistrationJSON117) ([]byte, []byte, []byte, error) {
	if c.Type != "public-key" {
		return nil, nil, nil, errors.New("credential.type должен быть public-key")
	}
	raw, err := decodeWebAuthnB64117(firstNonEmpty(c.RawID, c.ID), 2048)
	if err != nil {
		return nil, nil, nil, errors.New("rawId invalid")
	}
	client, err := decodeWebAuthnB64117(c.Response.ClientDataJSON, 64*1024)
	if err != nil {
		return nil, nil, nil, errors.New("clientDataJSON invalid")
	}
	att, err := decodeWebAuthnB64117(c.Response.AttestationObject, 256*1024)
	if err != nil {
		return nil, nil, nil, errors.New("attestationObject invalid")
	}
	return raw, client, att, nil
}
func decodeAssertionCredential117(c webauthnAssertionJSON117) ([]byte, []byte, []byte, []byte, []byte, error) {
	if c.Type != "public-key" {
		return nil, nil, nil, nil, nil, errors.New("credential.type должен быть public-key")
	}
	raw, err := decodeWebAuthnB64117(firstNonEmpty(c.RawID, c.ID), 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	client, err := decodeWebAuthnB64117(c.Response.ClientDataJSON, 64*1024)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	authData, err := decodeWebAuthnB64117(c.Response.AuthenticatorData, 64*1024)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sig, err := decodeWebAuthnB64117(c.Response.Signature, 16*1024)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	var handle []byte
	if strings.TrimSpace(c.Response.UserHandle) != "" {
		handle, err = decodeWebAuthnB64117(c.Response.UserHandle, 1024)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	return raw, client, authData, sig, handle, nil
}
func decodeWebAuthnB64117(v string, max int) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("empty base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > max {
		return nil, errors.New("decoded value size invalid")
	}
	return b, nil
}
func decodeJSONLimited117(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 512*1024+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
func normalizeTransports117(in []string) []string {
	allowed := map[string]bool{"usb": true, "nfc": true, "ble": true, "smart-card": true, "hybrid": true, "internal": true}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		v := strings.ToLower(strings.TrimSpace(raw))
		if allowed[v] && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func metadataString117(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return strings.TrimSpace(v)
}
func metadataStrings117(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := []string{}
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
func currentRequirementStrength117(req string) string {
	switch normalizeMFARequirement117(req) {
	case mfaRequired117:
		return "mfa"
	case mfaPhishingResistant117:
		return "phishing-resistant"
	default:
		return "single-factor"
	}
}
func freshAuth117(c authClaims, strength string, maxAge time.Duration) bool {
	return authStrengthLevel117(c.AuthStrength) >= authStrengthLevel117(strength) && c.AuthTime > 0 && time.Since(time.Unix(c.AuthTime, 0)) <= maxAge
}
func writeStepUpRequired117(w http.ResponseWriter, strength string) {
	errorBody := map[string]any{"code": http.StatusPreconditionRequired, "message": "требуется свежая step-up authentication", "requiredAuthStrength": strength, "passkeyBegin": "POST /api/v1/auth/passkeys/step-up/begin"}
	if authStrengthLevel117(strength) <= authStrengthLevel117("mfa") {
		errorBody["totpStepUp"] = "POST /api/v1/auth/mfa/step-up/totp"
	}
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": errorBody})
}

func (s Server) requireFreshAuth117(permission, strength string, maxAge time.Duration, next http.HandlerFunc) http.Handler {
	return s.requirePermission(permission, func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.adminClaims(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
			return
		}
		if s.writeRiskRequirement0126(w, claims) {
			return
		}
		if !freshAuth117(claims, strength, maxAge) {
			writeStepUpRequired117(w, strength)
			return
		}
		next(w, r)
	})
}
