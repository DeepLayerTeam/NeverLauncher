package oidcconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IDTokenSigningAlgs                []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresIn        int64  `json:"expires_in,omitempty"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type Connector struct {
	cfg          RuntimeConfig
	client       *http.Client
	transport    *http.Transport
	mu           sync.RWMutex
	discovery    discoveryDocument
	keys         []jwk
	refreshedAt  time.Time
	issuerPolicy IssuerPolicy
}

func New(ctx context.Context, input Config) (*Connector, error) {
	return NewWithIssuerPolicy(ctx, input, ExactIssuerPolicy{})
}

func NewWithIssuerPolicy(ctx context.Context, input Config, policy IssuerPolicy) (*Connector, error) {
	if policy == nil {
		policy = ExactIssuerPolicy{}
	}
	cfg, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	client, transport, err := newHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("Транспорт OIDC-коннектора %q: %w", cfg.ID, err)
	}
	c := &Connector{cfg: cfg, client: client, transport: transport, issuerPolicy: policy}
	refreshCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeoutValue)
	defer cancel()
	if err := c.refreshMetadata(refreshCtx); err != nil {
		c.Close()
		return nil, fmt.Errorf("Обнаружение OIDC-коннектора %q: %w", cfg.ID, err)
	}
	return c, nil
}
func (c *Connector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.cfg.ID, DisplayName: c.cfg.DisplayName, Version: providerVersion, Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth, authconnector.CapabilityTokenRefresh, authconnector.CapabilityEmail, authconnector.CapabilityGroups, authconnector.CapabilityRoles}}
}
func (c *Connector) Health(ctx context.Context) error {
	if c == nil || c.client == nil {
		return authconnector.NewError(authconnector.ErrUnavailable, "Клиент провайдера OIDC недоступен")
	}
	c.mu.RLock()
	fresh := time.Since(c.refreshedAt) < 5*time.Minute
	c.mu.RUnlock()
	if fresh {
		return nil
	}
	return c.refreshMetadata(ctx)
}
func (c *Connector) BeginBrowserAuth(ctx context.Context, req authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	if !c.cfg.RedirectAllowed(req.RedirectURI) {
		return authconnector.BrowserAuthStart{}, authconnector.NewError(authconnector.ErrMisconfigured, "URI перенаправления OIDC не зарегистрирован")
	}
	if len(req.State) < 32 || len(req.Nonce) < 32 || len(req.PKCEChallenge) < 43 {
		return authconnector.BrowserAuthStart{}, authconnector.NewError(authconnector.ErrMisconfigured, "Некорректное подтверждение state/nonce/PKCE для OIDC")
	}
	c.mu.RLock()
	endpoint := c.discovery.AuthorizationEndpoint
	c.mu.RUnlock()
	u, err := url.Parse(endpoint)
	if err != nil {
		return authconnector.BrowserAuthStart{}, authconnector.WrapError(authconnector.ErrMisconfigured, "Некорректный адрес авторизации OIDC", err)
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", req.PKCEChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return authconnector.BrowserAuthStart{AuthorizationURL: u.String(), State: req.State, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}, nil
}
func (c *Connector) CompleteBrowserAuth(ctx context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	if !c.cfg.RedirectAllowed(cb.RedirectURI) || strings.TrimSpace(cb.Code) == "" || len(cb.Code) > 8192 || len(cb.PKCEVerifier) < 43 || len(cb.PKCEVerifier) > 128 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Некорректный ответ авторизации OIDC")
	}
	tok, err := c.exchangeCode(ctx, cb)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	verified, err := c.verifyTokenWithRefresh(ctx, tok.IDToken, cb.Nonce, true)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrInvalidCredentials, "Не удалось проверить токен идентификации OIDC", err)
	}
	if err := validateAccessTokenHash(verified.Claims, verified.Header.Alg, tok.AccessToken); err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrInvalidCredentials, "Не удалось проверить хеш токена доступа OIDC", err)
	}
	claims := cloneMap(verified.Claims)
	if c.cfg.UserInfoMode != "disabled" && tok.AccessToken != "" {
		extra, err := c.userInfo(ctx, tok.AccessToken)
		if err != nil && c.cfg.UserInfoMode == "required" {
			return authconnector.Authentication{}, err
		}
		if err == nil {
			if sub, _ := extra["sub"].(string); sub == "" || sub != claimString(claims, "sub") {
				return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrMisconfigured, "Поле sub в OIDC UserInfo не совпадает с токеном идентификации")
			}
			for k, v := range extra {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	}
	identity, methods, err := c.identityFromClaims(claims)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	expires := time.Time{}
	if tok.ExpiresIn > 0 {
		expires = time.Now().UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return authconnector.Authentication{Identity: identity, AuthMethods: methods, ProviderToken: tok.RefreshToken, ExpiresAt: expires}, nil
}
func (c *Connector) Refresh(ctx context.Context, refreshToken string) (authconnector.Authentication, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" || len(refreshToken) > 16384 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Недействительный токен обновления OIDC")
	}
	c.mu.RLock()
	endpoint := c.discovery.TokenEndpoint
	c.mu.RUnlock()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {c.cfg.ClientID}}
	tok, err := c.doTokenRequest(ctx, endpoint, form)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	if tok.IDToken == "" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrMisconfigured, "Ответ обновления OIDC не содержит id_token")
	}
	verified, err := c.verifyTokenWithRefresh(ctx, tok.IDToken, "", false)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrInvalidCredentials, "Не удалось проверить обновлённый токен идентификации OIDC", err)
	}
	identity, methods, err := c.identityFromClaims(verified.Claims)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	next := tok.RefreshToken
	if next == "" {
		next = refreshToken
	}
	return authconnector.Authentication{Identity: identity, AuthMethods: methods, ProviderToken: next}, nil
}
func (c *Connector) Close() error {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}
func (c *Connector) ProvisioningMode() string { return c.cfg.Provisioning.Mode }
func (c *Connector) DefaultRole() string      { return c.cfg.Provisioning.DefaultRole }
func (c *Connector) DefaultRedirectURI() string {
	if len(c.cfg.RedirectURIs) == 0 {
		return ""
	}
	return c.cfg.RedirectURIs[0]
}

// EndSessionURL формирует URL выхода через интерфейс провайдера, если метаданные
// содержат end_session_endpoint. Это намеренно отделено от завершения сеанса Never.
func (c *Connector) EndSessionURL(postLogoutRedirectURI string) (string, error) {
	c.mu.RLock()
	endpoint := c.discovery.EndSessionEndpoint
	c.mu.RUnlock()
	if strings.TrimSpace(endpoint) == "" {
		return "", authconnector.NewError(authconnector.ErrUnsupported, "Поставщик OIDC не объявляет end_session_endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", authconnector.WrapError(authconnector.ErrMisconfigured, "Некорректный end_session_endpoint поставщика OIDC", err)
	}
	if v := strings.TrimSpace(postLogoutRedirectURI); v != "" {
		q := u.Query()
		q.Set("post_logout_redirect_uri", v)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func (c *Connector) exchangeCode(ctx context.Context, cb authconnector.BrowserAuthCallback) (tokenResponse, error) {
	c.mu.RLock()
	endpoint := c.discovery.TokenEndpoint
	c.mu.RUnlock()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Code}, "redirect_uri": {cb.RedirectURI}, "client_id": {c.cfg.ClientID}, "code_verifier": {cb.PKCEVerifier}}
	return c.doTokenRequest(ctx, endpoint, form)
}
func (c *Connector) doTokenRequest(ctx context.Context, endpoint string, form url.Values) (tokenResponse, error) {
	if c.cfg.TokenEndpointAuthMethod == "client_secret_post" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.TokenEndpointAuthMethod == "client_secret_basic" {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return tokenResponse{}, authconnector.WrapError(authconnector.ErrUnavailable, "Ошибка запроса к адресу выдачи токенов OIDC", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		return tokenResponse{}, authconnector.WrapError(authconnector.ErrUnavailable, "Чтение ответа с токеном OIDC", err)
	}
	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return tokenResponse{}, authconnector.NewError(authconnector.ErrUnavailable, "Ответ с токеном OIDC превышает настроенный предел")
	}
	var out tokenResponse
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return tokenResponse{}, authconnector.WrapError(authconnector.ErrMisconfigured, "Адрес выдачи токенов OIDC вернул некорректный JSON", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.Error != "" {
		code := strings.TrimSpace(out.Error)
		message := "Конечная точка токенов OIDC отклонила предоставление доступа"
		if code != "" {
			message += ": " + code
		}
		switch code {
		case "invalid_client", "unauthorized_client", "unsupported_grant_type":
			return tokenResponse{}, authconnector.NewError(authconnector.ErrMisconfigured, message)
		case "server_error", "temporarily_unavailable":
			return tokenResponse{}, authconnector.NewError(authconnector.ErrUnavailable, message)
		default:
			return tokenResponse{}, authconnector.NewError(authconnector.ErrInvalidCredentials, message)
		}
	}
	if !strings.EqualFold(out.TokenType, "Bearer") || out.AccessToken == "" {
		return tokenResponse{}, authconnector.NewError(authconnector.ErrMisconfigured, "В ответе OIDC отсутствует Bearer access_token")
	}
	return out, nil
}

func (c *Connector) refreshMetadata(ctx context.Context) error {
	discoveryURL := strings.TrimSuffix(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	var doc discoveryDocument
	if err := c.doJSON(req, &doc); err != nil {
		return err
	}
	if err := c.issuerPolicy.ValidateDiscoveryIssuer(c.cfg.Issuer, doc.Issuer); err != nil {
		return err
	}
	for name, raw := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI} {
		if err := c.validateDiscoveredURL(name, raw); err != nil {
			return err
		}
	}
	if doc.UserInfoEndpoint != "" {
		if err := c.validateDiscoveredURL("userinfo_endpoint", doc.UserInfoEndpoint); err != nil {
			return err
		}
	}
	if doc.EndSessionEndpoint != "" {
		if err := c.validateDiscoveredURL("end_session_endpoint", doc.EndSessionEndpoint); err != nil {
			return err
		}
	}
	if len(doc.TokenEndpointAuthMethodsSupported) > 0 && !contains(doc.TokenEndpointAuthMethodsSupported, c.cfg.TokenEndpointAuthMethod) {
		return fmt.Errorf("Провайдер не объявляет способ авторизации эндпоинта токенов %q", c.cfg.TokenEndpointAuthMethod)
	}
	if len(doc.IDTokenSigningAlgs) > 0 {
		ok := false
		for _, alg := range doc.IDTokenSigningAlgs {
			if c.cfg.AlgAllowed(alg) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("У провайдера и коннектора нет общего алгоритма подписи ID-токенов")
		}
	}
	jwksReq, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.JWKSURI, nil)
	if err != nil {
		return err
	}
	jwksReq.Header.Set("Accept", "application/json")
	var set jwkSet
	if err := c.doJSON(jwksReq, &set); err != nil {
		return fmt.Errorf("Загрузка JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return errors.New("JWKS не содержит ключей")
	}
	if len(set.Keys) > 128 {
		return errors.New("JWKS содержит слишком много ключей")
	}
	if err := validateJWKS(set.Keys, c.cfg); err != nil {
		return err
	}
	c.mu.Lock()
	c.discovery = doc
	c.keys = append([]jwk(nil), set.Keys...)
	c.refreshedAt = time.Now().UTC()
	c.mu.Unlock()
	return nil
}
func (c *Connector) verifyTokenWithRefresh(ctx context.Context, raw, nonce string, requireNonce bool) (verifiedToken, error) {
	c.mu.RLock()
	keys := append([]jwk(nil), c.keys...)
	c.mu.RUnlock()
	c.mu.RLock()
	discoveredIssuer := c.discovery.Issuer
	c.mu.RUnlock()
	verified, err := verifyIDTokenWithPolicy(raw, keys, c.cfg, discoveredIssuer, c.issuerPolicy, nonce, requireNonce)
	if err == nil {
		return verified, nil
	}
	if refreshErr := c.refreshMetadata(ctx); refreshErr != nil {
		return verifiedToken{}, fmt.Errorf("Ошибка: %v; обновление JWKS: %w", err, refreshErr)
	}
	c.mu.RLock()
	keys = append([]jwk(nil), c.keys...)
	c.mu.RUnlock()
	c.mu.RLock()
	discoveredIssuer = c.discovery.Issuer
	c.mu.RUnlock()
	return verifyIDTokenWithPolicy(raw, keys, c.cfg, discoveredIssuer, c.issuerPolicy, nonce, requireNonce)
}
func (c *Connector) userInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	c.mu.RLock()
	endpoint := c.discovery.UserInfoEndpoint
	c.mu.RUnlock()
	if endpoint == "" {
		return nil, authconnector.NewError(authconnector.ErrMisconfigured, "У провайдера OIDC отсутствует userinfo_endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	out := map[string]any{}
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Connector) doJSON(req *http.Request, out any) error {
	resp, err := c.client.Do(req)
	if err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "Ошибка запроса к вышестоящему провайдеру OIDC", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return authconnector.NewError(authconnector.ErrUnavailable, "Ответ вышестоящего сервера OIDC превышает настроенный предел")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return authconnector.NewError(authconnector.ErrUnavailable, fmt.Sprintf("Внешний провайдер OIDC вернул HTTP %d", resp.StatusCode))
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "application/json") && !strings.Contains(ct, "+json") {
		return authconnector.NewError(authconnector.ErrMisconfigured, "Вышестоящий сервер OIDC вернул ответ не в формате JSON")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return authconnector.WrapError(authconnector.ErrMisconfigured, "Вышестоящий провайдер OIDC вернул некорректный JSON", err)
	}
	return nil
}
func (c *Connector) validateDiscoveredURL(name, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("Для обнаружения конфигурации поставщика OIDC %s требуется: абсолютный URL HTTPS", name)
	}
	if !hostAllowed(strings.ToLower(u.Hostname()), c.cfg.HostAllowlist) {
		return fmt.Errorf("Хост обнаружения %s %q отсутствует в hostAllowlist", name, u.Hostname())
	}
	return nil
}
func (c *Connector) identityFromClaims(claims map[string]any) (authconnector.Identity, []string, error) {
	subject := claimString(claims, c.cfg.Claims.Subject)
	if subject == "" || len(subject) > 512 {
		return authconnector.Identity{}, nil, authconnector.NewError(authconnector.ErrMisconfigured, "Отсутствует или некорректно поле субъекта OIDC")
	}
	email := claimString(claims, c.cfg.Claims.Email)
	if c.cfg.RequireVerifiedEmail && email != "" {
		verified, _ := claimValue(claims, "email_verified").(bool)
		if !verified {
			return authconnector.Identity{}, nil, authconnector.NewError(authconnector.ErrIdentityDisabled, "Адрес электронной почты OIDC не подтверждён")
		}
	}
	groups, err := claimStrings(claims, c.cfg.Claims.Groups)
	if err != nil {
		return authconnector.Identity{}, nil, authconnector.WrapError(authconnector.ErrMisconfigured, "Некорректное поле групп OIDC", err)
	}
	roles, err := claimStrings(claims, c.cfg.Claims.Roles)
	if err != nil {
		return authconnector.Identity{}, nil, authconnector.WrapError(authconnector.ErrMisconfigured, "Некорректное поле ролей OIDC", err)
	}
	methods, _ := claimStrings(claims, "amr")
	if len(methods) == 0 {
		methods = []string{"oidc"}
	}
	return authconnector.Identity{Issuer: claimString(claims, "iss"), Subject: subject, Email: email, Username: claimString(claims, c.cfg.Claims.Username), DisplayName: claimString(claims, c.cfg.Claims.DisplayName), Groups: groups, Roles: roles, Claims: cloneMap(claims)}, methods, nil
}
func claimValue(claims map[string]any, path string) any {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}
func claimString(claims map[string]any, path string) string {
	v, _ := claimValue(claims, path).(string)
	return strings.TrimSpace(v)
}
func claimStrings(claims map[string]any, path string) ([]string, error) {
	v := claimValue(claims, path)
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return nil, nil
		}
		return []string{strings.TrimSpace(x)}, nil
	case []any:
		out := []string{}
		seen := map[string]struct{}{}
		if len(x) > 256 {
			return nil, errors.New("Превышено допустимое число значений")
		}
		for _, raw := range x {
			s, ok := raw.(string)
			if !ok {
				return nil, errors.New("Массив содержит значение, не являющееся строкой")
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if len(s) > 256 {
				return nil, errors.New("Слишком длинное значение")
			}
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, errors.New("Утверждение токена не является строкой или массивом строк")
	}
}
func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

var _ authconnector.BrowserAuthenticator = (*Connector)(nil)
var _ authconnector.TokenRefresher = (*Connector)(nil)
