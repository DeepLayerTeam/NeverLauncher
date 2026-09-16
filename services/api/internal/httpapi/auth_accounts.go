package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type authLoginRequest struct {
	Email        string `json:"email"`
	Identifier   string `json:"identifier,omitempty"`
	Password     string `json:"password"`
	TOTP         string `json:"totp,omitempty"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
	DeviceID     string `json:"deviceId,omitempty"`
	ProviderID   string `json:"providerId,omitempty"`
}

type authRefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s Server) authCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.authCapabilitiesPayload(s.Version)})
}

func (s Server) authPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion":     apiContractVersion,
		"toolVersion":       s.Version,
		"algorithm":         "Argon2id",
		"minimumLength":     12,
		"recommendedLength": 16,
		"requirements":      []string{"unique password", "no common password", "no project name", "server-side pepper", "rate-limited verification"},
		"reset":             map[string]any{"tokenTtlMinutes": 30, "singleUse": true, "revokeSessions": true, "audit": true},
	}})
}

func (s Server) authSessionPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.sessionPolicyPayload(s.Version)})
}

func (s Server) authAccounts(w http.ResponseWriter, r *http.Request) {
	users := s.Repo.ListUsers()
	items := make([]map[string]any, 0, len(users))
	for _, user := range users {
		items = append(items, sanitizeUserAccount(user))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "accounts-enforced", "items": items}})
}

func (s Server) authRoles(w http.ResponseWriter, r *http.Request) {
	roles := s.Repo.ListRoles()
	items := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		items = append(items, map[string]any{"id": role.ID, "name": role.Name, "description": role.Description, "permissions": role.Permissions})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items, "scopeModel": []string{"global", "project", "profile", "channel", "device-session"}}})
}

func (s Server) authLoginAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": s.Repo.ListAuditEvents(), "redaction": []string{"token", "password", "totp", "recoveryCode", "refreshToken"}}})
}

func (s Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	identifier := strings.TrimSpace(firstNonEmpty(req.Identifier, req.Email))
	rateKey := strings.ToLower(identifier)
	if identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "identifier/email и password обязательны")
		return
	}
	if allowed, retry := s.State.Security.allowLogin(rateKey, clientIP(r)); !allowed {
		writeError(w, http.StatusTooManyRequests, "слишком много неудачных входов; повторите после "+retry.Format(time.RFC3339))
		return
	}
	result, authErr := s.Federation.AuthenticatePassword(r.Context(), req.ProviderID, authconnector.PasswordRequest{Identifier: identifier, Secret: req.Password})
	if authErr != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("auth-login-failed")
		status := federationHTTPStatus112(authErr)
		if status >= 500 {
			writeError(w, status, "auth provider временно недоступен")
			return
		}
		if status == http.StatusForbidden {
			writeError(w, status, "учётная запись недоступна или identity не связана")
			return
		}
		if status == http.StatusBadRequest {
			writeError(w, status, "auth provider не поддерживает password login")
			return
		}
		if status == http.StatusConflict {
			writeError(w, status, "external identity конфликтует с существующей учётной записью; требуется явное связывание")
			return
		}
		writeError(w, http.StatusUnauthorized, "неверный email или пароль")
		return
	}
	user := result.User
	mfa, mfaErr := s.evaluateLoginMFA117(user, result.AuthMethods, req.TOTP, req.RecoveryCode)
	if mfaErr != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("auth-mfa-failed")
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-mfa-failed-" + time.Now().UTC().Format("20060102150405"), Actor: user.Email, Action: "auth:mfa:failed", Target: mfaErr.Error(), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusUnauthorized, "требуется действительный настроенный метод MFA")
		return
	}
	deviceID := firstNonEmpty(req.DeviceID, "desktop-client")
	if mfa.NeedPasskey {
		continuation, err := s.startPasskeyMFAContinuation117(user, result.Provider.ID, result.Identity.ID, deviceID, mfa.Methods)
		if err != nil {
			writeError(w, http.StatusForbidden, "MFA policy требует зарегистрированный passkey")
			return
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-passkey-required-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:mfa:passkey-required", Target: result.Provider.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": continuation})
		return
	}
	s.State.Security.recordLoginSuccess(rateKey, clientIP(r))
	_ = s.flushPersistenceState950("auth-login-success")
	accessToken, refreshToken, session, err := s.issueLoginSessionWithAuth(user, r, deviceID, mfa.Methods, mfa.Strength, time.Now().UTC(), result.Identity.ID, result.Provider.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось создать серверную сессию")
		return
	}
	if strings.TrimSpace(result.ProviderToken) != "" {
		if err := s.saveProviderCredential116(user, result.Identity, result.ProviderToken, false); err != nil {
			s.State.AuthSessions.revoke(session.ID, "provider-credential-persistence-failed")
			writeError(w, http.StatusInternalServerError, "не удалось безопасно сохранить provider credential")
			return
		}
	}
	if updated, err := s.Repo.TouchUserLogin(user.ID); err == nil {
		user = updated
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-login-" + time.Now().UTC().Format("20060102150405"), Actor: user.Email, Action: "auth:login", Target: session.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-federation-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:federation:authenticated", Target: result.Provider.ID + "/" + result.Identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "authenticated",
		"provider":      result.Provider.ID,
		"identity":      map[string]any{"id": result.Identity.ID, "provider": result.Identity.Provider, "subject": result.Identity.Subject},
		"authMethods":   mfa.Methods,
		"user":          sanitizeUserAccount(user),
		"session":       sanitizeSessionRecord(session),
		"tokens":        map[string]any{"accessToken": accessToken, "accessTokenTtlMinutes": int(accessTokenTTL.Minutes()), "refreshToken": refreshToken, "refreshTokenTtlDays": int(refreshTokenTTL.Hours() / 24), "rotation": true},
		"next":          []string{"store refresh token in secure storage", "use access token for protected endpoints", "refresh before expiry", "re-login after revoke"},
	}})
}

func (s Server) authRefresh(w http.ResponseWriter, r *http.Request) {
	var req authRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		writeError(w, http.StatusBadRequest, "refreshToken обязателен")
		return
	}
	session, newRefreshToken, err := s.State.AuthSessions.rotate(req.RefreshToken, r)
	_ = s.flushPersistenceState950("auth-refresh-rotate")
	if err != nil {
		if errors.Is(err, errRefreshTokenReuseDetected) {
			s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-refresh-reuse-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: "unknown", Action: "auth:refresh:reuse-detected", Target: "refresh-token-family", IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		}
		writeError(w, http.StatusUnauthorized, "refresh token недействителен или отозван")
		return
	}
	user, err := s.Repo.GetUser(session.UserID)
	if err != nil || user.Status == "disabled" {
		s.State.AuthSessions.revoke(session.ID, "user-disabled-or-missing")
		writeError(w, http.StatusUnauthorized, "пользователь недоступен")
		return
	}
	accessToken, err := s.issueAccessToken(user, session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось выпустить access token")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-refresh-" + time.Now().UTC().Format("20060102150405"), Actor: user.Email, Action: "auth:refresh", Target: session.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "rotated", "session": sanitizeSessionRecord(session), "tokens": map[string]any{"accessToken": accessToken, "accessTokenTtlMinutes": int(accessTokenTTL.Minutes()), "refreshToken": newRefreshToken, "refreshTokenTtlDays": int(refreshTokenTTL.Hours() / 24)}}})
}

func (s Server) authRefreshPlan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "implemented", "endpoint": "POST /api/v1/auth/refresh", "steps": []string{"verify refresh token hash", "detect revoked/expired session", "rotate refresh token", "issue new access token", "write session audit event"}, "ttl": map[string]any{"accessTokenMinutes": int(accessTokenTTL.Minutes()), "refreshTokenDays": int(refreshTokenTTL.Hours() / 24)}}})
}

func (s Server) authLogout(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	s.State.AuthSessions.revoke(claims.SessionID, "auth-logout")
	_ = s.flushPersistenceState950("auth-logout")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-logout-" + time.Now().UTC().Format("20060102150405"), Actor: claims.Email, Action: "auth:logout", Target: claims.SessionID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "logged-out", "sessionId": claims.SessionID}})
}

func (s Server) authAccountSessions(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userId"))
	user, err := s.Repo.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.accountSessionsPayload(s.Version, user)})
}

func (s Server) authRevokeAccountSessions(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userId"))
	user, err := s.Repo.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	revoked := s.State.AuthSessions.revokeUser(user.ID, "admin-revoke")
	_ = s.flushPersistenceState950("auth-admin-revoke")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-revoke-" + time.Now().UTC().Format("20060102150405"), Actor: s.adminActor(r), Action: "auth:sessions:revoke", Target: user.Email, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "revoked", "revokedSessions": revoked, "user": sanitizeUserAccount(user), "items": s.State.AuthSessions.listByUser(user.ID)}})
}

func (s Server) desktopAuthPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": desktopAuthPolicyPayload(s.Version)})
}

func (s Server) authCapabilitiesPayload(version string) map[string]any {
	return map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   version,
		"status":        "federation-core-active",
		"capabilities":  []string{"connector-sdk", "federation-core", "canonical-identity-resolution", "explicit-identity-linking", "sql-auth-provider", "http-auth-provider", "oidc-auth-provider", "microsoft-auth-provider", "encrypted-provider-credentials", "provider-credential-rotation", "jit-federated-provisioning", "identifier-password-login", "server-side-session-registry", "session-management-2", "session-device-management", "session-risk-state", "provider-session-revocation", "jwt-access-tokens", "access-token-key-rotation", "access-refresh-tokens", "refresh-token-rotation", "session-revocation", "disabled-user-block", "rbac-middleware", "project-role-bindings", "login-audit", "desktop-secure-storage", "totp-enrollment", "totp-login-enforcement", "passkeys-webauthn", "passwordless-passkey-login", "mfa-policy", "phishing-resistant-step-up", "recovery-codes", "password-reset-tokens", "email-verification-tokens", "login-rate-limit", "minecraft-auth-compatibility-2", "minecraft-session-adapter", "yggdrasil-authlib"},
		"providers":     s.Federation.Providers(),
		"roles":         []string{"owner", "admin", "release-manager", "support", "viewer", "player"},
		"sessions":      s.State.AuthSessions.summary(),
		"passkeys":      s.State.Passkeys.summary(),
	}
}

func (s Server) sessionPolicyPayload(version string) map[string]any {
	return map[string]any{"schemaVersion": apiContractVersion, "toolVersion": version, "status": "enforced", "accessTokenTtlMinutes": int(accessTokenTTL.Minutes()), "refreshTokenTtlDays": int(refreshTokenTTL.Hours() / 24), "rotation": true, "reuseDetection": true, "maxSessionsPerUser": maxSessionsPerUser, "revocationTriggers": []string{"logout", "password-reset", "role-change", "user-disable", "admin-revoke"}, "authStrengths": []string{"single-factor", "mfa", "phishing-resistant"}, "stepUpFreshnessMinutes": 5, "accessTokenFormat": "JWT/JWS HS256", "accessTokenClaims": []string{"iss", "aud", "sub", "sid", "jti", "iat", "exp", "kid(header)", "auth_time", "amr"}, "riskStates": []string{"normal", "elevated", "compromised"}, "sessionBackend": s.State.AuthSessions.summary(), "passkeyBackend": s.State.Passkeys.summary()}
}

func desktopAuthPolicyPayload(version string) map[string]any {
	return map[string]any{"schemaVersion": apiContractVersion, "toolVersion": version, "status": "desktop-auth-enforced", "loginEndpoint": "POST /api/v1/auth/login", "refreshEndpoint": "POST /api/v1/auth/refresh", "logoutEndpoint": "POST /api/v1/auth/logout", "secureStorage": map[string]any{"required": true, "linux": "secret-service/kwallet", "windows": "credential-manager", "macos": "keychain", "fallbackPlaintext": false}, "restore": map[string]any{"onStart": true, "refreshBeforeExpiry": true, "clearOnLogout": true}, "screens": []string{"identifier-password", "session-active", "session-expired", "project-access-denied"}}
}

func (s Server) accountSessionsPayload(version string, user model.User) map[string]any {
	items := s.State.AuthSessions.listByUser(user.ID)
	return map[string]any{"schemaVersion": apiContractVersion, "toolVersion": version, "user": sanitizeUserAccount(user), "items": items, "summary": map[string]any{"count": len(items)}, "actions": []string{"revoke-session", "revoke-user-sessions", "logout-all"}}
}

func sanitizeUserAccount(user model.User) map[string]any {
	return map[string]any{"id": user.ID, "email": user.Email, "displayName": user.DisplayName, "roleId": user.RoleID, "status": user.Status, "projectRoles": user.ProjectRoles, "passwordUpdatedAt": user.PasswordUpdatedAt, "lastLoginAt": user.LastLoginAt, "createdAt": user.CreatedAt, "updatedAt": user.UpdatedAt}
}
