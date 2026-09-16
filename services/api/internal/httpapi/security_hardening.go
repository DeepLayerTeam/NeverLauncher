package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	securityHardeningSchema902 = apiContractVersion
	totpStepSeconds            = 30
	passwordResetTTL           = 30 * time.Minute
	emailVerificationTTL       = 24 * time.Hour
	loginFailureWindow         = 10 * time.Minute
	loginLockoutDuration       = 15 * time.Minute
	loginFailureLimit          = 5
)

type securityHardeningStore struct {
	mu             sync.Mutex
	mfa            map[string]mfaRecord
	failedLogins   map[string]loginFailureRecord
	passwordResets map[string]oneTimeSecurityToken
	emailTokens    map[string]oneTimeSecurityToken
	emailVerified  map[string]bool
	recoveryUseLog []map[string]any
	persistent     *securityPostgres111
}

type mfaRecord struct {
	PendingSecret string            `json:"pendingSecret,omitempty"`
	ActiveSecret  string            `json:"-"`
	Enabled       bool              `json:"enabled"`
	Recovery      map[string]string `json:"-"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type loginFailureRecord struct {
	Count        int       `json:"count"`
	FirstFailure time.Time `json:"firstFailure"`
	LastFailure  time.Time `json:"lastFailure"`
	LockoutUntil time.Time `json:"lockoutUntil,omitempty"`
}

type oneTimeSecurityToken struct {
	UserID    string    `json:"userId"`
	Email     string    `json:"email"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expiresAt"`
	Used      bool      `json:"used"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"createdAt"`
}

type totpVerifyRequest902 struct {
	Code string `json:"code"`
}

type recoveryCodeRequest902 struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

type passwordResetRequest902 struct {
	Email    string `json:"email"`
	Token    string `json:"token"`
	Password string `json:"password"`
}

type emailVerificationRequest902 struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

func (s Server) securityHardeningStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": s.securityHardeningPayload902("security-hardening")})
}

func (s Server) ecosystemSecurityHardening(w http.ResponseWriter, r *http.Request) {
	payload := s.securityHardeningPayload902("ecosystem-security-hardening")
	payload["ecosystemGate"] = "required-after-9.0.1-stabilization"
	payload["release"] = "NeverLauncher 0.10.0 Security Hardening"
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": payload})
}

func (s Server) securityHardeningPayload902(kind string) map[string]any {
	return map[string]any{
		"schemaVersion": securityHardeningSchema902,
		"toolVersion":   s.Version,
		"kind":          kind,
		"mode":          "launcherops-ecosystem-platform",
		"status":        "security-hardened",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"implemented": []string{
			"TOTP enrollment with RFC 6238 verification",
			"TOTP enforcement during admin/player login when enabled",
			"WebAuthn Level 3 passkey registration and passwordless authentication with user verification",
			"MFA 2.0 policies: optional, required, phishing-resistant",
			"fresh step-up authentication for critical operations",
			"single-use recovery codes with SHA-256 hashing",
			"single-use password reset tokens with session revocation",
			"single-use email verification tokens",
			"IP/email login failure lockout",
			"security audit events for MFA, reset, verification and lockout flows",
		},
		"endpoints": []string{
			"GET /api/v1/operations/compliance",
			"GET /api/v1/operations/compliance",
			"POST /api/v1/auth/passkeys/register/begin",
			"POST /api/v1/auth/passkeys/register/complete",
			"POST /api/v1/auth/passkeys/login/begin",
			"POST /api/v1/auth/passkeys/login/complete",
			"POST /api/v1/auth/passkeys/step-up/begin",
			"POST /api/v1/auth/passkeys/step-up/complete",
			"PUT /api/v1/auth/mfa/policy",
			"POST /api/v1/auth/mfa/step-up/totp",
			"POST /api/v1/auth/totp/enroll",
			"POST /api/v1/auth/totp/verify",
			"POST /api/v1/auth/totp/disable",
			"POST /api/v1/auth/recovery-codes/regenerate",
			"POST /api/v1/auth/recovery-codes/consume",
			"POST /api/v1/auth/password-reset/request",
			"POST /api/v1/auth/password-reset/confirm",
			"POST /api/v1/auth/email-verification/request",
			"POST /api/v1/auth/email-verification/confirm",
		},
		"policy": map[string]any{
			"passwordHashing":          "Argon2id/PHC for all new passwords",
			"legacyHashMigration":      "sha256 accepted only for existing legacy admin users until password reset",
			"totpAlgorithm":            "HMAC-SHA1, 30 second step, 6 digits",
			"webauthn":                 "Level 3; UV required; discoverable credentials; ES256/Ed25519/RS256",
			"mfaPolicy":                []string{"optional", "required", "phishing-resistant"},
			"stepUpFreshnessMinutes":   5,
			"recoveryCodes":            "generated once, stored hashed, consumed once",
			"passwordResetTokenTtlMin": int(passwordResetTTL.Minutes()),
			"emailVerificationTtlHour": int(emailVerificationTTL.Hours()),
			"loginFailureLimit":        loginFailureLimit,
			"lockoutMinutes":           int(loginLockoutDuration.Minutes()),
		},
		"state":    s.State.Security.summary(),
		"passkeys": s.State.Passkeys.summary(),
	}
}

func (s Server) authTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	secret, err := generateTOTPSecret902()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать TOTP secret")
		return
	}
	if err := s.State.Security.startTOTPEnrollment(claims.Sub, secret); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить TOTP enrollment")
		return
	}
	_ = s.flushPersistenceState950("totp-enroll")
	issuer := "NeverLauncher"
	account := claims.Email
	provisioning := "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?secret=" + url.QueryEscape(secret) + "&issuer=" + url.QueryEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("totp-enroll"), Actor: claims.Email, Action: "auth:totp:enroll", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{
		"schemaVersion":   securityHardeningSchema902,
		"toolVersion":     s.Version,
		"status":          "pending-verification",
		"secret":          secret,
		"provisioningUri": provisioning,
		"algorithm":       "TOTP/HMAC-SHA1/30s/6digits",
		"next":            []string{"add secret to authenticator", "POST /api/v1/auth/totp/verify with current code", "regenerate recovery codes"},
	}})
}

func (s Server) authTOTPVerify(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req totpVerifyRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if !s.State.Security.finishTOTPEnrollment(claims.Sub, req.Code) {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("totp-verify-failed"), Actor: claims.Email, Action: "auth:totp:verify:failed", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusUnauthorized, "неверный TOTP код")
		return
	}
	_ = s.flushPersistenceState950("totp-verify")
	recovery, err := s.State.Security.generateRecoveryCodes(claims.Sub, 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать recovery codes")
		return
	}
	_ = s.flushPersistenceState950("recovery-codes-generated")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("totp-enabled"), Actor: claims.Email, Action: "auth:totp:enabled", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "totp-enabled", "recoveryCodes": recovery, "recoveryCodesShownOnce": true}})
}

func (s Server) authTOTPDisable(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req totpVerifyRequest902
	_ = json.NewDecoder(r.Body).Decode(&req)
	if s.State.Passkeys != nil && s.State.Passkeys.policy(claims.Sub) == mfaRequired117 && s.State.Passkeys.countByUser(claims.Sub) == 0 {
		writeError(w, http.StatusConflict, "MFA policy REQUIRED требует сохранить хотя бы один активный MFA method")
		return
	}
	if !s.State.Security.disableTOTP(claims.Sub, req.Code) {
		writeError(w, http.StatusUnauthorized, "неверный TOTP код или TOTP не включён")
		return
	}
	_ = s.flushPersistenceState950("totp-disabled")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("totp-disabled"), Actor: claims.Email, Action: "auth:totp:disabled", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "totp-disabled"}})
}

func (s Server) authRecoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	methodID := "mfa-totp-" + claims.Sub
	if !s.State.Security.totpEnabled(claims.Sub) {
		if s.State.Passkeys == nil || s.State.Passkeys.countByUser(claims.Sub) == 0 {
			writeError(w, http.StatusBadRequest, "сначала включите TOTP или зарегистрируйте passkey")
			return
		}
		methodID = "mfa-passkey-" + claims.Sub
	}
	codes, err := s.State.Security.generateRecoveryCodesForMethod117(claims.Sub, 10, methodID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать recovery codes")
		return
	}
	_ = s.flushPersistenceState950("recovery-regenerated")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("recovery-regenerated"), Actor: claims.Email, Action: "auth:recovery:regenerated", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "generated", "codes": codes, "shownOnce": true}})
}

func (s Server) authRecoveryCodeConsume(w http.ResponseWriter, r *http.Request) {
	var req recoveryCodeRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	user, ok := s.findUserByEmail(strings.ToLower(strings.TrimSpace(req.Email)))
	if !ok || !verifyPassword(req.Password, user.PasswordHash) || !s.State.Security.consumeRecoveryCode(user.ID, req.Code) {
		writeError(w, http.StatusUnauthorized, "recovery code отклонён")
		return
	}
	_ = s.flushPersistenceState950("recovery-consumed")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("recovery-consumed"), Actor: user.Email, Action: "auth:recovery:consumed", Target: user.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "accepted", "userId": user.ID}})
}

func (s Server) authPasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	user, ok := s.findUserByEmail(email)
	if !ok || user.Status == "disabled" {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "accepted", "delivery": "redacted-if-user-missing"}})
		return
	}
	token, rec, err := s.State.Security.createOneTimeToken(user.ID, user.Email, "password-reset", passwordResetTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать reset token")
		return
	}
	_ = s.flushPersistenceState950("password-reset-request")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("password-reset-request"), Actor: user.Email, Action: "auth:password-reset:requested", Target: user.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "issued", "delivery": "self-hosted-local-response", "token": token, "expiresAt": rec.ExpiresAt}})
}

func (s Server) authPasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "пароль должен быть не короче 12 символов")
		return
	}
	rec, ok := s.State.Security.consumeOneTimeToken(req.Token, "password-reset")
	if !ok {
		writeError(w, http.StatusUnauthorized, "reset token недействителен или истёк")
		return
	}
	user, err := s.Repo.SetUserPassword(rec.UserID, hashPassword(req.Password))
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	revoked := s.State.AuthSessions.revokeUser(user.ID, "password-reset")
	_ = s.flushPersistenceState950("password-reset-confirm")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("password-reset-confirm"), Actor: user.Email, Action: "auth:password-reset:confirmed", Target: user.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "password-updated", "user": sanitizeUserAccount(user), "revokedSessions": revoked}})
}

func (s Server) authEmailVerificationRequest(w http.ResponseWriter, r *http.Request) {
	var req emailVerificationRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	user, ok := s.findUserByEmail(email)
	if !ok || user.Status == "disabled" {
		writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "accepted", "delivery": "redacted-if-user-missing"}})
		return
	}
	token, rec, err := s.State.Security.createOneTimeToken(user.ID, user.Email, "email-verification", emailVerificationTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать verification token")
		return
	}
	_ = s.flushPersistenceState950("email-verification-request")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("email-verification-request"), Actor: user.Email, Action: "auth:email-verification:requested", Target: user.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "issued", "delivery": "self-hosted-local-response", "token": token, "expiresAt": rec.ExpiresAt}})
}

func (s Server) authEmailVerificationConfirm(w http.ResponseWriter, r *http.Request) {
	var req emailVerificationRequest902
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	rec, ok := s.State.Security.consumeOneTimeToken(req.Token, "email-verification")
	if !ok {
		writeError(w, http.StatusUnauthorized, "verification token недействителен или истёк")
		return
	}
	s.State.Security.setEmailVerified(rec.UserID, true)
	_ = s.flushPersistenceState950("email-verification-confirm")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: securityAuditID902("email-verification-confirm"), Actor: rec.Email, Action: "auth:email-verification:confirmed", Target: rec.UserID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": securityHardeningSchema902, "data": map[string]any{"schemaVersion": securityHardeningSchema902, "toolVersion": s.Version, "status": "email-verified", "userId": rec.UserID}})
}

func (s *securityHardeningStore) startTOTPEnrollment(userID, secret string) error {
	if s.persistent != nil {
		return s.persistent.startTOTPEnrollment(userID, secret)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.mfa[userID]
	rec.PendingSecret = secret
	rec.UpdatedAt = time.Now().UTC()
	if rec.Recovery == nil {
		rec.Recovery = map[string]string{}
	}
	s.mfa[userID] = rec
	return nil
}

func (s *securityHardeningStore) finishTOTPEnrollment(userID, code string) bool {
	if s.persistent != nil {
		return s.persistent.finishTOTPEnrollment(userID, code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.mfa[userID]
	if rec.PendingSecret == "" || !verifyTOTPCode902(rec.PendingSecret, code, time.Now().UTC()) {
		return false
	}
	rec.ActiveSecret = rec.PendingSecret
	rec.PendingSecret = ""
	rec.Enabled = true
	rec.UpdatedAt = time.Now().UTC()
	if rec.Recovery == nil {
		rec.Recovery = map[string]string{}
	}
	s.mfa[userID] = rec
	return true
}

func (s *securityHardeningStore) disableTOTP(userID, code string) bool {
	if s.persistent != nil {
		return s.persistent.disableTOTP(userID, code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.mfa[userID]
	if !rec.Enabled || !verifyTOTPCode902(rec.ActiveSecret, code, time.Now().UTC()) {
		return false
	}
	rec.Enabled = false
	rec.ActiveSecret = ""
	rec.PendingSecret = ""
	rec.UpdatedAt = time.Now().UTC()
	s.mfa[userID] = rec
	return true
}

func (s *securityHardeningStore) verifySecondFactor(userID, totp, recovery string) (bool, string) {
	if s.persistent != nil {
		return s.persistent.verifySecondFactor(userID, totp, recovery)
	}
	s.mu.Lock()
	rec := s.mfa[userID]
	s.mu.Unlock()
	if !rec.Enabled {
		return true, "mfa-not-enabled"
	}
	if verifyTOTPCode902(rec.ActiveSecret, totp, time.Now().UTC()) {
		return true, "totp-ok"
	}
	if s.consumeRecoveryCode(userID, recovery) {
		return true, "recovery-ok"
	}
	return false, "mfa-required"
}

func (s *securityHardeningStore) totpEnabled(userID string) bool {
	if s.persistent != nil {
		return s.persistent.totpEnabled(userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mfa[userID].Enabled
}

func (s *securityHardeningStore) ensurePasskeyMethod117(userID string, enabled bool) error {
	if s.persistent != nil {
		return s.persistent.ensurePasskeyMethod117(userID, enabled)
	}
	return nil
}

func (s *securityHardeningStore) generateRecoveryCodesForMethod117(userID string, count int, methodID string) ([]string, error) {
	if s.persistent != nil {
		return s.persistent.generateRecoveryCodesForMethod117(userID, count, methodID)
	}
	// Memory mode has no relational method foreign key; reuse the existing single-use store.
	s.mu.Lock()
	rec := s.mfa[userID]
	if rec.Recovery == nil {
		rec.Recovery = map[string]string{}
	}
	codes := make([]string, 0, count)
	fresh := map[string]string{}
	for i := 0; i < count; i++ {
		token, err := randomToken("nlrec")
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		code := strings.ToUpper(strings.ReplaceAll(token, "_", "-"))
		codes = append(codes, code)
		fresh[hashSecurityToken902(code)] = "active"
	}
	rec.Recovery = fresh
	rec.UpdatedAt = time.Now().UTC()
	s.mfa[userID] = rec
	s.mu.Unlock()
	return codes, nil
}

func (s *securityHardeningStore) generateRecoveryCodes(userID string, count int) ([]string, error) {
	if s.persistent != nil {
		return s.persistent.generateRecoveryCodes(userID, count)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.mfa[userID]
	if rec.Recovery == nil {
		rec.Recovery = map[string]string{}
	}
	codes := make([]string, 0, count)
	fresh := map[string]string{}
	for i := 0; i < count; i++ {
		token, err := randomToken("nlrec")
		if err != nil {
			return nil, err
		}
		code := strings.ToUpper(strings.ReplaceAll(token, "_", "-"))
		codes = append(codes, code)
		fresh[hashSecurityToken902(code)] = "active"
	}
	rec.Recovery = fresh
	rec.UpdatedAt = time.Now().UTC()
	s.mfa[userID] = rec
	return codes, nil
}

func (s *securityHardeningStore) consumeRecoveryCode(userID, code string) bool {
	if s.persistent != nil {
		return s.persistent.consumeRecoveryCode(userID, code)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.mfa[userID]
	if rec.Recovery == nil {
		return false
	}
	h := hashSecurityToken902(code)
	if rec.Recovery[h] != "active" {
		return false
	}
	rec.Recovery[h] = "used"
	rec.UpdatedAt = time.Now().UTC()
	s.mfa[userID] = rec
	s.recoveryUseLog = append(s.recoveryUseLog, map[string]any{"userId": userID, "usedAt": time.Now().UTC().Format(time.RFC3339)})
	return true
}

func (s *securityHardeningStore) createOneTimeToken(userID, email, purpose string, ttl time.Duration) (string, oneTimeSecurityToken, error) {
	token, err := randomToken("nlsec")
	if err != nil {
		return "", oneTimeSecurityToken{}, err
	}
	rec := oneTimeSecurityToken{UserID: userID, Email: email, TokenHash: hashSecurityToken902(token), Purpose: purpose, ExpiresAt: time.Now().UTC().Add(ttl), CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredLocked()
	if purpose == "password-reset" {
		s.passwordResets[rec.TokenHash] = rec
	} else {
		s.emailTokens[rec.TokenHash] = rec
	}
	return token, rec, nil
}

func (s *securityHardeningStore) consumeOneTimeToken(token, purpose string) (oneTimeSecurityToken, bool) {
	h := hashSecurityToken902(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredLocked()
	var rec oneTimeSecurityToken
	var ok bool
	if purpose == "password-reset" {
		rec, ok = s.passwordResets[h]
	} else {
		rec, ok = s.emailTokens[h]
	}
	if !ok || rec.Used || rec.ExpiresAt.Before(time.Now().UTC()) || rec.Purpose != purpose {
		return oneTimeSecurityToken{}, false
	}
	rec.Used = true
	if purpose == "password-reset" {
		s.passwordResets[h] = rec
	} else {
		s.emailTokens[h] = rec
	}
	return rec, true
}

func (s *securityHardeningStore) setEmailVerified(userID string, value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailVerified[userID] = value
}

func (s *securityHardeningStore) allowLogin(email, ip string) (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := loginKey902(email, ip)
	rec := s.failedLogins[key]
	now := time.Now().UTC()
	if rec.LockoutUntil.After(now) {
		return false, rec.LockoutUntil
	}
	return true, time.Time{}
}

func (s *securityHardeningStore) recordLoginFailure(email, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	key := loginKey902(email, ip)
	rec := s.failedLogins[key]
	if rec.FirstFailure.IsZero() || now.Sub(rec.FirstFailure) > loginFailureWindow {
		rec = loginFailureRecord{FirstFailure: now}
	}
	rec.Count++
	rec.LastFailure = now
	if rec.Count >= loginFailureLimit {
		rec.LockoutUntil = now.Add(loginLockoutDuration)
	}
	s.failedLogins[key] = rec
}

func (s *securityHardeningStore) recordLoginSuccess(email, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failedLogins, loginKey902(email, ip))
}

func (s *securityHardeningStore) clearExpiredLocked() {
	now := time.Now().UTC()
	for k, rec := range s.passwordResets {
		if rec.ExpiresAt.Before(now) || rec.Used {
			delete(s.passwordResets, k)
		}
	}
	for k, rec := range s.emailTokens {
		if rec.ExpiresAt.Before(now) || rec.Used {
			delete(s.emailTokens, k)
		}
	}
}

func (s *securityHardeningStore) summary() map[string]any {
	enabled := 0
	pending := 0
	activeRecovery := 0
	if s.persistent != nil {
		var err error
		enabled, pending, activeRecovery, err = s.persistent.summary()
		if err != nil {
			return map[string]any{"backend": "postgres-auth-core-0.11.1", "status": "unavailable", "error": err.Error()}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistent == nil {
		for _, rec := range s.mfa {
			if rec.Enabled {
				enabled++
			}
			if rec.PendingSecret != "" {
				pending++
			}
			for _, state := range rec.Recovery {
				if state == "active" {
					activeRecovery++
				}
			}
		}
	}
	locked := 0
	for _, rec := range s.failedLogins {
		if rec.LockoutUntil.After(time.Now().UTC()) {
			locked++
		}
	}
	backend := "in-process-dev-security-store"
	if s.persistent != nil {
		backend = "postgres-auth-core-0.11.1"
	}
	return map[string]any{"totpEnabledUsers": enabled, "totpPendingUsers": pending, "activeRecoveryCodes": activeRecovery, "activePasswordResetTokens": len(s.passwordResets), "activeEmailVerificationTokens": len(s.emailTokens), "verifiedEmails": len(s.emailVerified), "lockedLoginKeys": locked, "mfaBackend": backend}
}

func generateTOTPSecret902() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func verifyTOTPCode902(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 || secret == "" {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		if currentTOTPCode902(secret, now.Add(time.Duration(offset*totpStepSeconds)*time.Second)) == code {
			return true
		}
	}
	return false
}

func currentTOTPCode902(secret string, now time.Time) string {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "000000"
	}
	counter := uint64(now.Unix() / totpStepSeconds)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := (int(sum[offset])&0x7f)<<24 | (int(sum[offset+1])&0xff)<<16 | (int(sum[offset+2])&0xff)<<8 | (int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", binaryCode%1000000)
}

func hashSecurityToken902(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func loginKey902(email, ip string) string {
	return strings.ToLower(strings.TrimSpace(email)) + "|" + strings.TrimSpace(ip)
}

func securityAuditID902(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102150405") + "-" + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))[0:8]
}
