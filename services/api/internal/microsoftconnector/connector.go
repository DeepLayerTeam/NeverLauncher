package microsoftconnector

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/oidcconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type Connector struct {
	cfg  RuntimeConfig
	oidc *oidcconnector.Connector
}

func New(ctx context.Context, input Config) (*Connector, error) {
	cfg, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	policy := microsoftIssuerPolicy{authorityBase: cfg.AuthorityBase, tenant: cfg.Tenant, tenantMode: cfg.TenantMode, allowedTenantIDs: cfg.AllowedTenantSet}
	base, err := oidcconnector.NewWithIssuerPolicy(ctx, cfg.OIDC, policy)
	if err != nil {
		return nil, fmt.Errorf("Microsoft connector %q: %w", cfg.ID, err)
	}
	return &Connector{cfg: cfg, oidc: base}, nil
}

func (c *Connector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.cfg.ID, DisplayName: c.cfg.DisplayName, Version: providerVersion, Capabilities: []authconnector.Capability{authconnector.CapabilityBrowserAuth, authconnector.CapabilityTokenRefresh, authconnector.CapabilityEmail, authconnector.CapabilityGroups, authconnector.CapabilityRoles}}
}

func (c *Connector) Health(ctx context.Context) error { return c.oidc.Health(ctx) }
func (c *Connector) Close() error                     { return c.oidc.Close() }
func (c *Connector) ProvisioningMode() string         { return c.cfg.Provisioning.Mode }
func (c *Connector) DefaultRole() string              { return c.cfg.Provisioning.DefaultRole }
func (c *Connector) DefaultRedirectURI() string       { return c.oidc.DefaultRedirectURI() }
func (c *Connector) RoleMappings() map[string]string  { return cloneStringsMap(c.cfg.RoleMappings) }
func (c *Connector) TenantMode() string               { return c.cfg.TenantMode }
func (c *Connector) ProviderKind() string             { return "microsoft" }

func (c *Connector) BeginBrowserAuth(ctx context.Context, req authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	start, err := c.oidc.BeginBrowserAuth(ctx, req)
	if err != nil {
		return start, err
	}
	u, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		return authconnector.BrowserAuthStart{}, authconnector.WrapError(authconnector.ErrMisconfigured, "Microsoft authorization URL is invalid", err)
	}
	q := u.Query()
	if c.cfg.Prompt != "" {
		q.Set("prompt", c.cfg.Prompt)
	}
	if c.cfg.DomainHint != "" {
		q.Set("domain_hint", c.cfg.DomainHint)
	}
	if c.cfg.LoginHint != "" {
		q.Set("login_hint", c.cfg.LoginHint)
	}
	u.RawQuery = q.Encode()
	start.AuthorizationURL = u.String()
	return start, nil
}

func (c *Connector) CompleteBrowserAuth(ctx context.Context, cb authconnector.BrowserAuthCallback) (authconnector.Authentication, error) {
	auth, err := c.oidc.CompleteBrowserAuth(ctx, cb)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	return c.normalizeAuthentication(auth)
}

func (c *Connector) Refresh(ctx context.Context, refreshToken string) (authconnector.Authentication, error) {
	auth, err := c.oidc.Refresh(ctx, refreshToken)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	return c.normalizeAuthentication(auth)
}

func (c *Connector) ProviderLogoutURL(postLogoutRedirectURI string) (string, error) {
	postLogoutRedirectURI = strings.TrimSpace(postLogoutRedirectURI)
	if !c.cfg.PostLogoutRedirectAllowed(postLogoutRedirectURI) {
		return "", authconnector.NewError(authconnector.ErrMisconfigured, "Microsoft post-logout redirect URI is not registered")
	}
	return c.oidc.EndSessionURL(postLogoutRedirectURI)
}

func (c *Connector) normalizeAuthentication(auth authconnector.Authentication) (authconnector.Authentication, error) {
	claims := auth.Identity.Claims
	tid := strings.ToLower(strings.TrimSpace(stringClaim(claims, "tid")))
	oid := strings.ToLower(strings.TrimSpace(stringClaim(claims, "oid")))
	if !validGUID(tid) || !validGUID(oid) {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrMisconfigured, "Microsoft identity requires immutable tid and oid GUID claims")
	}
	// tid+oid is stable across applications inside a tenant and cannot be silently
	// replaced by a mutable email/UPN. It also keeps identically-shaped objects from
	// different tenants distinct.
	auth.Identity.Subject = tid + ":" + oid
	if auth.Identity.Username == "" {
		auth.Identity.Username = strings.TrimSpace(stringClaim(claims, "preferred_username"))
	}
	if auth.Identity.DisplayName == "" {
		auth.Identity.DisplayName = strings.TrimSpace(stringClaim(claims, "name"))
	}
	if auth.Identity.Email == "" {
		candidate := strings.TrimSpace(stringClaim(claims, "email"))
		if candidate == "" {
			candidate = auth.Identity.Username
		}
		if strings.Contains(candidate, "@") && len(candidate) <= 512 {
			auth.Identity.Email = candidate
		}
	}
	seen := map[string]struct{}{}
	methods := make([]string, 0, len(auth.AuthMethods)+1)
	for _, method := range append(auth.AuthMethods, "microsoft") {
		method = strings.TrimSpace(method)
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	auth.AuthMethods = methods
	return auth, nil
}
