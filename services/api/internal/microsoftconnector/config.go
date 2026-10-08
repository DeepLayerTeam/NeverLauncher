package microsoftconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/oidcconnector"
)

const providerVersion = "0.11.6"
const personalMicrosoftTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

type ProvisioningConfig struct {
	Mode        string `json:"mode,omitempty"`
	DefaultRole string `json:"defaultRole,omitempty"`
}

type Config struct {
	ID                      string             `json:"id"`
	DisplayName             string             `json:"displayName,omitempty"`
	Cloud                   string             `json:"cloud,omitempty"`
	Tenant                  string             `json:"tenant,omitempty"`
	AllowedTenantIDs        []string           `json:"allowedTenantIds,omitempty"`
	ClientID                string             `json:"clientId"`
	ClientSecretEnv         string             `json:"clientSecretEnv,omitempty"`
	ClientSecretFile        string             `json:"clientSecretFile,omitempty"`
	TokenEndpointAuthMethod string             `json:"tokenEndpointAuthMethod,omitempty"`
	RedirectURIs            []string           `json:"redirectUris"`
	PostLogoutRedirectURIs  []string           `json:"postLogoutRedirectUris,omitempty"`
	Scopes                  []string           `json:"scopes,omitempty"`
	Prompt                  string             `json:"prompt,omitempty"`
	DomainHint              string             `json:"domainHint,omitempty"`
	LoginHint               string             `json:"loginHint,omitempty"`
	RoleMappings            map[string]string  `json:"roleMappings,omitempty"`
	Provisioning            ProvisioningConfig `json:"provisioning,omitempty"`
	CAFile                  string             `json:"caFile,omitempty"`
	AllowedCIDRs            []string           `json:"allowedCidrs,omitempty"`
	RequestTimeout          string             `json:"requestTimeout,omitempty"`
	ConnectTimeout          string             `json:"connectTimeout,omitempty"`
	ClockSkew               string             `json:"clockSkew,omitempty"`
	MaxResponseBytes        int64              `json:"maxResponseBytes,omitempty"`

	// authorityUrl is intentionally advanced: normal deployments should use cloud.
	// A non-Microsoft authority requires allowCustomAuthority=true and remains subject
	// to the same HTTPS, host allowlist and DNS/IP SSRF checks as generic OIDC.
	AuthorityURL         string `json:"authorityUrl,omitempty"`
	AllowCustomAuthority bool   `json:"allowCustomAuthority,omitempty"`
}

type RuntimeConfig struct {
	Config
	AuthorityBase         string
	TenantMode            string
	AllowedTenantSet      map[string]struct{}
	PostLogoutRedirectSet map[string]struct{}
	OIDC                  oidcconnector.Config
}

func LoadConfigs(jsonValue, filePath string) ([]Config, error) {
	jsonValue = strings.TrimSpace(jsonValue)
	filePath = strings.TrimSpace(filePath)
	if jsonValue != "" && filePath != "" {
		return nil, errors.New("configure only one of NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON or NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE")
	}
	if jsonValue == "" && filePath == "" {
		return nil, nil
	}
	raw := []byte(jsonValue)
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read Microsoft providers file: %w", err)
		}
		raw = data
	}
	var configs []Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode Microsoft providers configuration: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("Microsoft providers configuration contains trailing JSON data")
	}
	if len(configs) == 0 {
		return nil, errors.New("Microsoft providers configuration is empty")
	}
	return configs, nil
}

func Normalize(input Config) (RuntimeConfig, error) {
	cfg := input
	cfg.ID = strings.ToLower(strings.TrimSpace(cfg.ID))
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.Cloud = strings.ToLower(strings.TrimSpace(cfg.Cloud))
	cfg.Tenant = strings.ToLower(strings.TrimSpace(cfg.Tenant))
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecretEnv = strings.TrimSpace(cfg.ClientSecretEnv)
	cfg.ClientSecretFile = strings.TrimSpace(cfg.ClientSecretFile)
	cfg.TokenEndpointAuthMethod = strings.ToLower(strings.TrimSpace(cfg.TokenEndpointAuthMethod))
	cfg.Prompt = strings.TrimSpace(cfg.Prompt)
	cfg.DomainHint = strings.TrimSpace(cfg.DomainHint)
	cfg.LoginHint = strings.TrimSpace(cfg.LoginHint)
	cfg.AuthorityURL = strings.TrimSuffix(strings.TrimSpace(cfg.AuthorityURL), "/")
	cfg.CAFile = strings.TrimSpace(cfg.CAFile)
	cfg.Provisioning.Mode = strings.ToLower(strings.TrimSpace(cfg.Provisioning.Mode))
	cfg.Provisioning.DefaultRole = strings.TrimSpace(cfg.Provisioning.DefaultRole)

	if err := validateProviderID(cfg.ID); err != nil {
		return RuntimeConfig{}, err
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Microsoft"
	}
	if len(cfg.DisplayName) > 128 {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: displayName exceeds 128 characters", cfg.ID)
	}
	if cfg.Cloud == "" {
		cfg.Cloud = "global"
	}
	cloudAuthority := ""
	switch cfg.Cloud {
	case "global":
		cloudAuthority = "https://login.microsoftonline.com"
	case "usgov":
		cloudAuthority = "https://login.microsoftonline.us"
	case "china":
		cloudAuthority = "https://login.partner.microsoftonline.cn"
	case "custom":
		if !cfg.AllowCustomAuthority {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: cloud=custom requires allowCustomAuthority=true", cfg.ID)
		}
	default:
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: cloud must be global, usgov, china or custom", cfg.ID)
	}
	if cfg.AuthorityURL == "" {
		cfg.AuthorityURL = cloudAuthority
	} else if cloudAuthority != "" && cfg.AuthorityURL != cloudAuthority && !cfg.AllowCustomAuthority {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: authorityUrl does not match cloud %q", cfg.ID, cfg.Cloud)
	}
	authority, err := url.Parse(cfg.AuthorityURL)
	if err != nil || authority.Scheme != "https" || authority.Host == "" || authority.User != nil || authority.RawQuery != "" || authority.Fragment != "" || (authority.Path != "" && authority.Path != "/") {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: authorityUrl must be an HTTPS origin", cfg.ID)
	}
	cfg.AuthorityURL = strings.TrimSuffix(authority.String(), "/")

	if cfg.Tenant == "" {
		cfg.Tenant = "common"
	}
	tenantMode := cfg.Tenant
	switch cfg.Tenant {
	case "common", "organizations", "consumers":
	default:
		if !validGUID(cfg.Tenant) {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: tenant must be common, organizations, consumers or an immutable tenant GUID", cfg.ID)
		}
		tenantMode = "tenant"
		cfg.Tenant = strings.ToLower(cfg.Tenant)
	}
	if cfg.ClientID == "" || !validGUID(cfg.ClientID) {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: clientId must be an application GUID", cfg.ID)
	}

	allowedTenantSet := map[string]struct{}{}
	for _, raw := range cfg.AllowedTenantIDs {
		v := strings.ToLower(strings.TrimSpace(raw))
		if !validGUID(v) {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: invalid allowedTenantIds value %q", cfg.ID, raw)
		}
		allowedTenantSet[v] = struct{}{}
	}
	if tenantMode == "tenant" {
		if len(allowedTenantSet) > 0 {
			if _, ok := allowedTenantSet[cfg.Tenant]; !ok || len(allowedTenantSet) != 1 {
				return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: single-tenant provider cannot allow other tenants", cfg.ID)
			}
		}
		allowedTenantSet[cfg.Tenant] = struct{}{}
	}
	if cfg.Tenant == "consumers" {
		if len(allowedTenantSet) > 0 {
			if _, ok := allowedTenantSet[personalMicrosoftTenantID]; !ok || len(allowedTenantSet) != 1 {
				return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: consumers authority only accepts the Microsoft personal-account tenant", cfg.ID)
			}
		}
		allowedTenantSet[personalMicrosoftTenantID] = struct{}{}
	}
	if cfg.Tenant == "organizations" {
		if _, ok := allowedTenantSet[personalMicrosoftTenantID]; ok {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: organizations authority cannot allow personal Microsoft accounts", cfg.ID)
		}
	}

	if cfg.TokenEndpointAuthMethod == "" {
		if cfg.ClientSecretEnv != "" || cfg.ClientSecretFile != "" {
			cfg.TokenEndpointAuthMethod = "client_secret_post"
		} else {
			cfg.TokenEndpointAuthMethod = "none"
		}
	}
	if cfg.TokenEndpointAuthMethod != "client_secret_post" && cfg.TokenEndpointAuthMethod != "client_secret_basic" && cfg.TokenEndpointAuthMethod != "none" {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: unsupported tokenEndpointAuthMethod", cfg.ID)
	}
	if cfg.ClientSecretEnv != "" && cfg.ClientSecretFile != "" {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: configure only one clientSecretEnv/clientSecretFile", cfg.ID)
	}
	if cfg.ClientSecretFile != "" && !filepath.IsAbs(cfg.ClientSecretFile) {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: clientSecretFile must be absolute", cfg.ID)
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: caFile must be absolute", cfg.ID)
	}

	if len(cfg.RedirectURIs) == 0 {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: at least one redirectUri is required", cfg.ID)
	}
	postLogoutSet := map[string]struct{}{}
	for _, raw := range cfg.PostLogoutRedirectURIs {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Fragment != "" {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: invalid postLogoutRedirectUri %q", cfg.ID, raw)
		}
		postLogoutSet[v] = struct{}{}
	}

	// Microsoft v2 requires offline_access to issue refresh tokens. openid/profile
	// are mandatory here because tid/oid are part of the connector trust boundary.
	scopeSet := map[string]struct{}{"openid": {}, "profile": {}, "email": {}, "offline_access": {}}
	for _, scope := range cfg.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: invalid scope", cfg.ID)
		}
		scopeSet[scope] = struct{}{}
	}
	scopes := make([]string, 0, len(scopeSet))
	for _, required := range []string{"openid", "profile", "email", "offline_access"} {
		scopes = append(scopes, required)
		delete(scopeSet, required)
	}
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	cfg.Scopes = scopes

	if cfg.Prompt != "" {
		switch cfg.Prompt {
		case "login", "none", "consent", "select_account":
		default:
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: unsupported prompt %q", cfg.ID, cfg.Prompt)
		}
	}
	if len(cfg.DomainHint) > 256 || len(cfg.LoginHint) > 512 {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: domainHint/loginHint is too long", cfg.ID)
	}
	if cfg.Provisioning.Mode == "" {
		cfg.Provisioning.Mode = "explicit-only"
	}
	if cfg.Provisioning.Mode != "explicit-only" && cfg.Provisioning.Mode != "jit" {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: provisioning.mode must be explicit-only or jit", cfg.ID)
	}
	if cfg.Provisioning.Mode == "jit" && cfg.Provisioning.DefaultRole == "" {
		cfg.Provisioning.DefaultRole = "player"
	}

	issuer := cfg.AuthorityURL + "/" + cfg.Tenant + "/v2.0"
	oidcCfg := oidcconnector.Config{
		ID: cfg.ID, DisplayName: cfg.DisplayName, Issuer: issuer, ClientID: cfg.ClientID,
		ClientSecretEnv: cfg.ClientSecretEnv, ClientSecretFile: cfg.ClientSecretFile,
		TokenEndpointAuthMethod: cfg.TokenEndpointAuthMethod, RedirectURIs: append([]string(nil), cfg.RedirectURIs...),
		Scopes: append([]string(nil), cfg.Scopes...), HostAllowlist: []string{authority.Hostname()}, AllowedCIDRs: append([]string(nil), cfg.AllowedCIDRs...),
		CAFile: cfg.CAFile, RequestTimeout: cfg.RequestTimeout, ConnectTimeout: cfg.ConnectTimeout, MaxResponseBytes: cfg.MaxResponseBytes,
		AllowedIDTokenAlgs: []string{"RS256"}, ClockSkew: cfg.ClockSkew, UserInfoMode: "disabled",
		Claims:       oidcconnector.ClaimMapping{Subject: "sub", Email: "email", Username: "preferred_username", DisplayName: "name", Groups: "groups", Roles: "roles"},
		RoleMappings: cloneStringsMap(cfg.RoleMappings), Provisioning: oidcconnector.ProvisioningConfig{Mode: cfg.Provisioning.Mode, DefaultRole: cfg.Provisioning.DefaultRole},
	}
	// Validate the delegated generic configuration now as part of Microsoft config
	// loading, before any network call is attempted.
	if _, err := oidcconnector.Normalize(oidcCfg); err != nil {
		return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q OIDC configuration: %w", cfg.ID, err)
	}
	for _, raw := range cfg.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return RuntimeConfig{}, fmt.Errorf("Microsoft connector %q: invalid allowedCidrs value %q", cfg.ID, raw)
		}
	}
	return RuntimeConfig{Config: cfg, AuthorityBase: cfg.AuthorityURL, TenantMode: tenantMode, AllowedTenantSet: allowedTenantSet, PostLogoutRedirectSet: postLogoutSet, OIDC: oidcCfg}, nil
}

func (c RuntimeConfig) PostLogoutRedirectAllowed(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	_, ok := c.PostLogoutRedirectSet[v]
	return ok
}

func validateProviderID(v string) error {
	if v == "" {
		return errors.New("Microsoft connector id is required")
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("invalid Microsoft connector id %q", v)
		}
	}
	return nil
}

func validGUID(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) != 36 || v[8] != '-' || v[13] != '-' || v[18] != '-' || v[23] != '-' {
		return false
	}
	for i, r := range v {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func cloneStringsMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// keep time imported as a compile-time guard for the configuration contract; the
// delegated OIDC normalizer owns the actual duration parsing.
var _ = time.Second
