package httpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const oidcTransactionTTL115 = 10 * time.Minute

type oidcBeginRequest115 struct {
	RedirectURI string `json:"redirectUri,omitempty"`
	DeviceID    string `json:"deviceId,omitempty"`
}
type oidcCompleteRequest115 struct {
	Code         string `json:"code"`
	State        string `json:"state"`
	Transaction  string `json:"transaction"`
	DeviceID     string `json:"deviceId,omitempty"`
	TOTP         string `json:"totp,omitempty"`
	RecoveryCode string `json:"recoveryCode,omitempty"`
}
type oidcTransaction115 struct {
	ProviderID   string `json:"providerId"`
	RedirectURI  string `json:"redirectUri"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkceVerifier"`
	DeviceID     string `json:"deviceId"`
	LinkUserID   string `json:"linkUserId,omitempty"`
	ExpiresAt    int64  `json:"exp"`
}

func (s Server) authOIDCBegin115(w http.ResponseWriter, r *http.Request) {
	var req oidcBeginRequest115
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	start, tx, err := s.beginOIDC115(r, r.PathValue("providerId"), req.RedirectURI, req.DeviceID)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "provider": strings.ToLower(strings.TrimSpace(r.PathValue("providerId"))), "authorizationUrl": start.AuthorizationURL, "state": start.State, "transaction": tx, "expiresAt": start.ExpiresAt}})
}

func (s Server) authOIDCStart115(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirectUri"))
	if redirectURI == "" {
		redirectURI = strings.TrimSuffix(strings.TrimSpace(s.Config.PublicURL), "/") + "/api/v1/auth/oidc/" + provider + "/callback"
	}
	start, tx, err := s.beginOIDC115(r, provider, redirectURI, r.URL.Query().Get("deviceId"))
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookieName115(provider), Value: tx, Path: "/api/v1/auth/oidc/" + provider + "/", HttpOnly: true, Secure: oidcCookieSecure115(s.Config.PublicURL), SameSite: http.SameSiteLaxMode, MaxAge: int(oidcTransactionTTL115.Seconds())})
	http.Redirect(w, r, start.AuthorizationURL, http.StatusFound)
}

func (s Server) authOIDCComplete115(w http.ResponseWriter, r *http.Request) {
	var req oidcCompleteRequest115
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	tx, err := s.openOIDCTransaction115(req.Transaction)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OIDC transaction недействителен или истёк")
		return
	}
	if req.DeviceID != "" {
		tx.DeviceID = req.DeviceID
	}
	s.completeOIDC115(w, r, tx, req.Code, req.State, req.TOTP, req.RecoveryCode)
}

func (s Server) authOIDCCallback115(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	cookie, err := r.Cookie(oidcCookieName115(provider))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OIDC transaction cookie отсутствует")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookieName115(provider), Value: "", Path: "/api/v1/auth/oidc/" + provider + "/", HttpOnly: true, Secure: oidcCookieSecure115(s.Config.PublicURL), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if upstreamErr := strings.TrimSpace(r.URL.Query().Get("error")); upstreamErr != "" {
		writeError(w, http.StatusUnauthorized, "OIDC provider отклонил авторизацию")
		return
	}
	tx, err := s.openOIDCTransaction115(cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OIDC transaction недействителен или истёк")
		return
	}
	s.completeOIDC115(w, r, tx, r.URL.Query().Get("code"), r.URL.Query().Get("state"), "", "")
}

func (s Server) beginOIDC115(r *http.Request, providerID, redirectURI, deviceID string) (authconnector.BrowserAuthStart, string, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if providerID == "" {
		return authconnector.BrowserAuthStart{}, "", federation.ErrProviderNotFound
	}
	connector, ok := s.Federation.Connector(providerID)
	if !ok {
		return authconnector.BrowserAuthStart{}, "", federation.ErrProviderNotFound
	}
	if strings.TrimSpace(redirectURI) == "" {
		if d, ok := connector.(interface{ DefaultRedirectURI() string }); ok {
			redirectURI = d.DefaultRedirectURI()
		}
	}
	if strings.TrimSpace(redirectURI) == "" {
		return authconnector.BrowserAuthStart{}, "", authconnector.NewError(authconnector.ErrMisconfigured, "OIDC redirect URI is required")
	}
	state, err := randomURLToken115(32)
	if err != nil {
		return authconnector.BrowserAuthStart{}, "", err
	}
	nonce, err := randomURLToken115(32)
	if err != nil {
		return authconnector.BrowserAuthStart{}, "", err
	}
	verifier, err := randomURLToken115(32)
	if err != nil {
		return authconnector.BrowserAuthStart{}, "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	start, err := s.Federation.BeginBrowserAuth(r.Context(), providerID, authconnector.BrowserAuthRequest{RedirectURI: redirectURI, State: state, Nonce: nonce, PKCEChallenge: challenge})
	if err != nil {
		return authconnector.BrowserAuthStart{}, "", err
	}
	tx := oidcTransaction115{ProviderID: providerID, RedirectURI: redirectURI, State: state, Nonce: nonce, PKCEVerifier: verifier, DeviceID: firstNonEmpty(strings.TrimSpace(deviceID), "oidc-browser"), ExpiresAt: time.Now().UTC().Add(oidcTransactionTTL115).Unix()}
	sealed, err := s.sealOIDCTransaction115(tx)
	if err != nil {
		return authconnector.BrowserAuthStart{}, "", err
	}
	return start, sealed, nil
}

func (s Server) completeOIDC115(w http.ResponseWriter, r *http.Request, tx oidcTransaction115, code, state, totp, recovery string) {
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if provider == "" || provider != tx.ProviderID || state == "" || state != tx.State || strings.TrimSpace(code) == "" {
		writeError(w, http.StatusUnauthorized, "OIDC authorization response недействителен")
		return
	}
	rateKey := "oidc:" + provider + ":" + clientIP(r)
	if allowed, retry := s.State.Security.allowLogin(rateKey, clientIP(r)); !allowed {
		writeError(w, http.StatusTooManyRequests, "слишком много неудачных входов; повторите после "+retry.Format(time.RFC3339))
		return
	}
	result, err := s.Federation.CompleteBrowserAuth(r.Context(), provider, authconnector.BrowserAuthCallback{RedirectURI: tx.RedirectURI, Code: code, State: state, Nonce: tx.Nonce, PKCEVerifier: tx.PKCEVerifier})
	if err != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("oidc-login-failed")
		s.writeOIDCError115(w, err)
		return
	}
	s.finishFederatedLogin115(w, r, result, tx.DeviceID, totp, recovery, rateKey)
}

func (s Server) finishFederatedLogin115(w http.ResponseWriter, r *http.Request, result federation.Result, deviceID, totp, recoveryCode, rateKey string) {
	user := result.User
	if err := s.saveProviderCredential116(user, result.Identity, result.ProviderToken, false); err != nil {
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-credential-failed-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:provider-credential:failed", Target: result.Provider.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusInternalServerError, "не удалось безопасно сохранить provider credential")
		return
	}
	mfa, mfaErr := s.evaluateLoginMFA117(user, result.AuthMethods, totp, recoveryCode)
	if mfaErr != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		_ = s.flushPersistenceState950("auth-mfa-failed")
		s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-mfa-failed-" + time.Now().UTC().Format("20060102150405"), Actor: user.Email, Action: "auth:mfa:failed", Target: mfaErr.Error(), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		writeError(w, http.StatusUnauthorized, "требуется действительный настроенный метод MFA")
		return
	}
	deviceID = firstNonEmpty(deviceID, "oidc-client")
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
	if updated, err := s.Repo.TouchUserLogin(user.ID); err == nil {
		user = updated
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-login-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:login", Target: session.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-federation-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:federation:authenticated", Target: result.Provider.ID + "/" + result.Identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "authenticated", "provider": result.Provider.ID, "identity": map[string]any{"id": result.Identity.ID, "provider": result.Identity.Provider, "subject": result.Identity.Subject}, "authMethods": mfa.Methods, "user": sanitizeUserAccount(user), "session": sanitizeSessionRecord(session), "tokens": map[string]any{"accessToken": accessToken, "accessTokenTtlMinutes": int(accessTokenTTL.Minutes()), "refreshToken": refreshToken, "refreshTokenTtlDays": int(refreshTokenTTL.Hours() / 24), "rotation": true}}})
}

func (s Server) writeOIDCError115(w http.ResponseWriter, err error) {
	status := federationHTTPStatus112(err)
	switch status {
	case http.StatusBadRequest:
		writeError(w, status, "OIDC provider не поддерживает browser login")
	case http.StatusForbidden:
		writeError(w, status, "учётная запись недоступна или identity не связана")
	case http.StatusConflict:
		writeError(w, status, "external identity конфликтует с существующей учётной записью; требуется явное связывание")
	case http.StatusServiceUnavailable:
		writeError(w, status, "OIDC provider временно недоступен")
	default:
		if status >= 500 {
			writeError(w, status, "ошибка OIDC provider")
		} else {
			writeError(w, http.StatusUnauthorized, "OIDC авторизация недействительна")
		}
	}
}

func (s Server) sealOIDCTransaction115(tx oidcTransaction115) (string, error) {
	raw, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	aead, err := s.oidcAEAD115()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, raw, []byte("NeverLauncher/OIDC/0.11.5"))
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}
func (s Server) openOIDCTransaction115(token string) (oidcTransaction115, error) {
	var tx oidcTransaction115
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return tx, err
	}
	aead, err := s.oidcAEAD115()
	if err != nil {
		return tx, err
	}
	if len(raw) <= aead.NonceSize() {
		return tx, errors.New("short OIDC transaction")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("NeverLauncher/OIDC/0.11.5"))
	if err != nil {
		return tx, err
	}
	if err := json.Unmarshal(plain, &tx); err != nil {
		return tx, err
	}
	if tx.ExpiresAt <= time.Now().UTC().Unix() || tx.ExpiresAt > time.Now().UTC().Add(oidcTransactionTTL115+time.Minute).Unix() {
		return tx, errors.New("expired OIDC transaction")
	}
	if tx.ProviderID == "" || tx.RedirectURI == "" || tx.State == "" || tx.Nonce == "" || tx.PKCEVerifier == "" {
		return tx, errors.New("incomplete OIDC transaction")
	}
	return tx, nil
}
func (s Server) oidcAEAD115() (cipher.AEAD, error) {
	secret := strings.TrimSpace(s.Config.AuthTokenSecret)
	if secret == "" {
		return nil, errors.New("auth token secret is empty")
	}
	key := sha256.Sum256([]byte("NeverLauncher/OIDC/transaction/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func randomURLToken115(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func oidcCookieName115(provider string) string {
	return "nl_oidc_" + strings.ReplaceAll(strings.ReplaceAll(provider, ".", "_"), "-", "_")
}
func oidcCookieSecure115(publicURL string) bool {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	return err == nil && strings.EqualFold(u.Scheme, "https")
}
