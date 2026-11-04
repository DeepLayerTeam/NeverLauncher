// Пакет javaauthconnector подключает явно разрешённых провайдеров идентичности JVM к
// существующей федерации. Канонический пользователь, роль или токен сеанса,
// предоставленные Java, не принимаются; MFA, привязка и выдача токенов остаются
// ответственностью федерации.
package javaauthconnector

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type Config struct {
	ID          string `json:"id"`
	ExtensionID string `json:"extensionId"`
	DisplayName string `json:"displayName"`
}

var validID = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,63}$`)

func (cfg Config) Validate() error {
	if !validID.MatchString(cfg.ID) || !validID.MatchString(cfg.ExtensionID) || strings.TrimSpace(cfg.DisplayName) == "" || len(cfg.DisplayName) > 120 {
		return errors.New("invalid Java identity provider configuration")
	}
	if cfg.ID == "local" {
		return errors.New("built-in provider cannot be overridden")
	}
	return nil
}

type Connector struct {
	config Config
	host   *extensionhost.Supervisor
}

func New(cfg Config, host *extensionhost.Supervisor) (*Connector, error) {
	if e := cfg.Validate(); e != nil {
		return nil, e
	}
	if host == nil {
		return nil, errors.New("Java extension host unavailable")
	}
	return &Connector{config: cfg, host: host}, nil
}
func (c *Connector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.config.ID, DisplayName: c.config.DisplayName, Version: "1.0.0", Capabilities: []authconnector.Capability{
		authconnector.CapabilityPasswordAuth, authconnector.CapabilityUserLookup, authconnector.CapabilityTokenRevoke,
	}}
}
func (c *Connector) rpc(ctx context.Context, method string, params any) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, authconnector.NewError(authconnector.ErrMisconfigured, "invalid Java request")
	}
	result, err := c.host.CallJavaRPC0304(ctx, extensionhost.Key{ExtensionID: c.config.ExtensionID, Scope: "global"}, method, raw)
	if err != nil {
		return nil, authconnector.NewError(authconnector.ErrUnavailable, "Java identity provider unavailable")
	}
	var response map[string]json.RawMessage
	if err = json.Unmarshal(result, &response); err != nil {
		return nil, authconnector.NewError(authconnector.ErrMisconfigured, "invalid Java identity response")
	}
	if fault, ok := response["errorCode"]; ok {
		var code string
		if json.Unmarshal(fault, &code) != nil {
			return nil, authconnector.NewError(authconnector.ErrMisconfigured, "invalid Java identity error")
		}
		allowed := map[authconnector.ErrorCode]bool{
			authconnector.ErrInvalidCredentials: true, authconnector.ErrIdentityDisabled: true, authconnector.ErrIdentityNotFound: true,
			authconnector.ErrConflict: true, authconnector.ErrUnsupported: true, authconnector.ErrUnavailable: true, authconnector.ErrMisconfigured: true,
		}
		if !allowed[authconnector.ErrorCode(code)] {
			code = string(authconnector.ErrMisconfigured)
		}
		return nil, authconnector.NewError(authconnector.ErrorCode(code), "Java identity provider rejected request")
	}
	return response, nil
}
func (c *Connector) Health(ctx context.Context) error {
	response, err := c.rpc(ctx, "auth.health", map[string]any{})
	if err != nil {
		return err
	}
	var available bool
	if json.Unmarshal(response["available"], &available) != nil || !available {
		return authconnector.NewError(authconnector.ErrUnavailable, "Java identity provider not selected")
	}
	return nil
}

type javaIdentity struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

func (v javaIdentity) validated() (authconnector.Identity, error) {
	id := authconnector.Identity{Issuer: v.Issuer, Subject: v.Subject, Email: v.Email, Username: v.Username, DisplayName: v.DisplayName}
	if err := authconnector.ValidateIdentity(id); err != nil {
		return id, err
	}
	if v.Issuer == "" {
		return id, authconnector.NewError(authconnector.ErrMisconfigured, "Java identity issuer is required")
	}
	return id, nil
}

type javaProof struct {
	Identity      javaIdentity `json:"identity"`
	AuthMethods   []string     `json:"authMethods"`
	ProviderToken string       `json:"providerToken"`
	ExpiresAt     int64        `json:"expiresAt"`
}

func decodeProof(raw json.RawMessage) (authconnector.Authentication, error) {
	var p javaProof
	if len(raw) == 0 || json.Unmarshal(raw, &p) != nil {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrMisconfigured, "malformed Java identity proof")
	}
	identity, err := p.Identity.validated()
	if err != nil {
		return authconnector.Authentication{}, err
	}
	if len(p.AuthMethods) == 0 || p.ExpiresAt < 0 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrMisconfigured, "invalid Java authentication proof")
	}
	result := authconnector.Authentication{Identity: identity, AuthMethods: p.AuthMethods, ProviderToken: p.ProviderToken}
	if p.ExpiresAt != 0 {
		result.ExpiresAt = time.Unix(p.ExpiresAt, 0).UTC()
		if !time.Now().Before(result.ExpiresAt) {
			return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "expired Java provider proof")
		}
	}
	if err = authconnector.ValidateAuthentication(result); err != nil {
		return authconnector.Authentication{}, err
	}
	return result, nil
}
func (c *Connector) AuthenticatePassword(ctx context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if strings.TrimSpace(req.Identifier) == "" || len(req.Identifier) > 512 || req.Secret == "" || len(req.Secret) > 4096 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	response, err := c.rpc(ctx, "auth.password", map[string]string{"identifier": req.Identifier, "secret": req.Secret})
	if err != nil {
		return authconnector.Authentication{}, err
	}
	return decodeProof(response["authentication"])
}
func (c *Connector) ResolveIdentity(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	if req.Subject == "" || len(req.Subject) > 512 {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "invalid subject")
	}
	response, err := c.rpc(ctx, "auth.resolve", map[string]string{"subject": req.Subject})
	if err != nil {
		return authconnector.Identity{}, err
	}
	var identity javaIdentity
	if len(response["identity"]) == 0 || json.Unmarshal(response["identity"], &identity) != nil {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrMisconfigured, "malformed Java identity")
	}
	parsed, err := identity.validated()
	if err != nil {
		return parsed, err
	}
	if parsed.Subject != req.Subject {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrMisconfigured, "Java identity subject mismatch")
	}
	return parsed, nil
}

// VerifyProviderSession проверяет токен провайдера, а НЕ JWT NeverLauncher, наличие
// прав или выдачу нового сеанса входа.
func (c *Connector) VerifyProviderSession(ctx context.Context, token string) (authconnector.Authentication, error) {
	if token == "" || len(token) > 16384 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid provider token")
	}
	response, err := c.rpc(ctx, "auth.session.verify", map[string]string{"providerToken": token})
	if err != nil {
		return authconnector.Authentication{}, err
	}
	return decodeProof(response["authentication"])
}
func (c *Connector) Revoke(ctx context.Context, req authconnector.RevokeRequest) error {
	if req.Subject == "" || len(req.Subject) > 512 || req.ProviderToken == "" || len(req.ProviderToken) > 16384 {
		return authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid provider token")
	}
	response, err := c.rpc(ctx, "auth.session.revoke", map[string]string{"subject": req.Subject, "providerToken": req.ProviderToken})
	if err != nil {
		return err
	}
	var revoked bool
	if json.Unmarshal(response["revoked"], &revoked) != nil || !revoked {
		return authconnector.NewError(authconnector.ErrUnavailable, "provider did not confirm revocation")
	}
	return nil
}

var _ authconnector.PasswordAuthenticator = (*Connector)(nil)
var _ authconnector.IdentityResolver = (*Connector)(nil)
var _ authconnector.Revoker = (*Connector)(nil)
