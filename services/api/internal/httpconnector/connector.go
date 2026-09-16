package httpconnector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type Connector struct {
	cfg       RuntimeConfig
	signed    *signedClient
	transport *http.Transport
}

func New(ctx context.Context, input Config) (*Connector, error) {
	cfg, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	client, transport, err := newHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("HTTP connector %q transport: %w", cfg.ID, err)
	}
	connector := &Connector{cfg: cfg, signed: newSignedClient(cfg, client), transport: transport}
	healthCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeoutDuration)
	defer cancel()
	if err := connector.Health(healthCtx); err != nil {
		connector.Close()
		return nil, fmt.Errorf("HTTP connector %q health check: %w", cfg.ID, err)
	}
	return connector, nil
}

func (c *Connector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{
		ID:          c.cfg.ID,
		DisplayName: c.cfg.DisplayName,
		Version:     providerVersion,
		Capabilities: []authconnector.Capability{
			authconnector.CapabilityPasswordAuth,
			authconnector.CapabilityTokenRefresh,
			authconnector.CapabilityTokenRevoke,
			authconnector.CapabilityUserLookup,
			authconnector.CapabilityEmail,
			authconnector.CapabilityGroups,
			authconnector.CapabilityRoles,
		},
	}
}

func (c *Connector) Health(ctx context.Context) error {
	if c == nil || c.signed == nil {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider client is unavailable")
	}
	var response healthResponse
	if err := c.signed.doJSON(ctx, http.MethodGet, c.cfg.Endpoints.Health, nil, &response); err != nil {
		return err
	}
	if err := validateProtocol(c.cfg, response.ProtocolVersion, response.Issuer); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(response.Status)) != "ok" {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider health status is not ok")
	}
	return nil
}

func (c *Connector) AuthenticatePassword(ctx context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || req.Secret == "" || len(identifier) > 512 || len(req.Secret) > 4096 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	envelope, err := baseRequest()
	if err != nil {
		return authconnector.Authentication{}, err
	}
	envelope.Identifier = identifier
	envelope.Password = req.Secret
	var response identityResponse
	if err := c.signed.doJSON(ctx, http.MethodPost, c.cfg.Endpoints.Authenticate, envelope, &response); err != nil {
		return authconnector.Authentication{}, err
	}
	identity, err := c.validateIdentityResponse(response, "")
	if err != nil {
		return authconnector.Authentication{}, err
	}
	methods, err := strictNormalizeStrings(response.AuthMethods, 32, 64)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider authMethods are invalid", err)
	}
	if len(methods) == 0 {
		methods = []string{"password"}
	}
	expires := time.Time{}
	if response.ExpiresAt != nil {
		expires = response.ExpiresAt.UTC()
	}
	return authconnector.Authentication{Identity: identity, AuthMethods: methods, ProviderToken: response.ProviderToken, ExpiresAt: expires}, nil
}

func (c *Connector) ResolveIdentity(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	subject := strings.TrimSpace(req.Subject)
	if subject == "" || len(subject) > 512 {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "HTTP identity subject is invalid")
	}
	envelope, err := baseRequest()
	if err != nil {
		return authconnector.Identity{}, err
	}
	envelope.Subject = subject
	var response identityResponse
	if err := c.signed.doJSON(ctx, http.MethodPost, c.cfg.Endpoints.Resolve, envelope, &response); err != nil {
		return authconnector.Identity{}, err
	}
	return c.validateIdentityResponse(response, subject)
}

func (c *Connector) Refresh(ctx context.Context, providerToken string) (authconnector.Authentication, error) {
	providerToken = strings.TrimSpace(providerToken)
	if providerToken == "" || len(providerToken) > 16384 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "provider token is invalid")
	}
	envelope, err := baseRequest()
	if err != nil {
		return authconnector.Authentication{}, err
	}
	envelope.ProviderToken = providerToken
	var response identityResponse
	if err := c.signed.doJSON(ctx, http.MethodPost, c.cfg.Endpoints.Refresh, envelope, &response); err != nil {
		return authconnector.Authentication{}, err
	}
	identity, err := c.validateIdentityResponse(response, "")
	if err != nil {
		return authconnector.Authentication{}, err
	}
	methods, err := strictNormalizeStrings(response.AuthMethods, 32, 64)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider authMethods are invalid", err)
	}
	expires := time.Time{}
	if response.ExpiresAt != nil {
		expires = response.ExpiresAt.UTC()
	}
	return authconnector.Authentication{Identity: identity, AuthMethods: methods, ProviderToken: response.ProviderToken, ExpiresAt: expires}, nil
}

func (c *Connector) Revoke(ctx context.Context, req authconnector.RevokeRequest) error {
	subject := strings.TrimSpace(req.Subject)
	token := strings.TrimSpace(req.ProviderToken)
	if subject == "" || token == "" || len(subject) > 512 || len(token) > 16384 {
		return authconnector.NewError(authconnector.ErrInvalidCredentials, "provider revoke request is invalid")
	}
	envelope, err := baseRequest()
	if err != nil {
		return err
	}
	envelope.Subject = subject
	envelope.ProviderToken = token
	var response actionResponse
	if err := c.signed.doJSON(ctx, http.MethodPost, c.cfg.Endpoints.Logout, envelope, &response); err != nil {
		return err
	}
	if err := validateProtocol(c.cfg, response.ProtocolVersion, response.Issuer); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(response.Status)) != "revoked" {
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider logout response status is invalid")
	}
	return nil
}

func (c *Connector) Close() error {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

func (c *Connector) ProvisioningMode() string { return c.cfg.Provisioning.Mode }
func (c *Connector) DefaultRole() string      { return c.cfg.Provisioning.DefaultRole }

func (c *Connector) validateIdentityResponse(response identityResponse, expectedSubject string) (authconnector.Identity, error) {
	if err := validateProtocol(c.cfg, response.ProtocolVersion, response.Issuer); err != nil {
		return authconnector.Identity{}, err
	}
	response.Subject = strings.TrimSpace(response.Subject)
	if response.Subject == "" || len(response.Subject) > 512 {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider returned invalid subject")
	}
	if expectedSubject != "" && response.Subject != expectedSubject {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider changed subject during identity resolution")
	}
	if len(response.Email) > 512 || len(response.Username) > 512 || len(response.DisplayName) > 1024 || len(response.ProviderToken) > 16384 {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider returned oversized identity fields")
	}
	groups, err := strictNormalizeStrings(response.Groups, 256, 256)
	if err != nil {
		return authconnector.Identity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider groups are invalid", err)
	}
	roles, err := strictNormalizeStrings(response.Roles, 256, 256)
	if err != nil {
		return authconnector.Identity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider roles are invalid", err)
	}
	claims := response.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return authconnector.Identity{
		Subject: response.Subject,
		Email:   strings.TrimSpace(response.Email), Username: strings.TrimSpace(response.Username), DisplayName: strings.TrimSpace(response.DisplayName),
		Groups: groups, Roles: roles, Claims: claims,
	}, nil
}

func baseRequest() (requestEnvelope, error) {
	id, err := randomHex(16)
	if err != nil {
		return requestEnvelope{}, authconnector.WrapError(authconnector.ErrUnavailable, "HTTP connector request id generation failed", err)
	}
	return requestEnvelope{ProtocolVersion: protocolVersion, RequestID: id, Timestamp: time.Now().UTC()}, nil
}

func strictNormalizeStrings(values []string, maxItems, maxLength int) ([]string, error) {
	if len(values) > maxItems {
		return nil, fmt.Errorf("too many values")
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > maxLength {
			return nil, fmt.Errorf("value exceeds %d bytes", maxLength)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

var _ authconnector.PasswordAuthenticator = (*Connector)(nil)
var _ authconnector.IdentityResolver = (*Connector)(nil)
var _ authconnector.TokenRefresher = (*Connector)(nil)
var _ authconnector.Revoker = (*Connector)(nil)
