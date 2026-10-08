package oidcconnector

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
)

const providerVersion = "0.11.5"

type ClaimMapping struct {
	Subject     string `json:"subject,omitempty"`
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Groups      string `json:"groups,omitempty"`
	Roles       string `json:"roles,omitempty"`
}

type ProvisioningConfig struct {
	Mode        string `json:"mode,omitempty"`
	DefaultRole string `json:"defaultRole,omitempty"`
}

type Config struct {
	ID                      string             `json:"id"`
	DisplayName             string             `json:"displayName,omitempty"`
	Issuer                  string             `json:"issuer"`
	ClientID                string             `json:"clientId"`
	ClientSecretEnv         string             `json:"clientSecretEnv,omitempty"`
	ClientSecretFile        string             `json:"clientSecretFile,omitempty"`
	TokenEndpointAuthMethod string             `json:"tokenEndpointAuthMethod,omitempty"`
	RedirectURIs            []string           `json:"redirectUris"`
	Scopes                  []string           `json:"scopes,omitempty"`
	HostAllowlist           []string           `json:"hostAllowlist,omitempty"`
	AllowedCIDRs            []string           `json:"allowedCidrs,omitempty"`
	CAFile                  string             `json:"caFile,omitempty"`
	RequestTimeout          string             `json:"requestTimeout,omitempty"`
	ConnectTimeout          string             `json:"connectTimeout,omitempty"`
	MaxResponseBytes        int64              `json:"maxResponseBytes,omitempty"`
	AllowedIDTokenAlgs      []string           `json:"allowedIdTokenAlgs,omitempty"`
	ClockSkew               string             `json:"clockSkew,omitempty"`
	UserInfoMode            string             `json:"userInfoMode,omitempty"`
	RequireVerifiedEmail    bool               `json:"requireVerifiedEmail,omitempty"`
	Claims                  ClaimMapping       `json:"claims,omitempty"`
	RoleMappings            map[string]string  `json:"roleMappings,omitempty"`
	Provisioning            ProvisioningConfig `json:"provisioning,omitempty"`
}

type RuntimeConfig struct {
	Config
	ParsedIssuer         *url.URL
	ClientSecret         string
	RequestTimeoutValue  time.Duration
	ConnectTimeoutValue  time.Duration
	ClockSkewValue       time.Duration
	ParsedAllowedCIDRs   []*net.IPNet
	redirectURISet       map[string]struct{}
	allowedIDTokenAlgSet map[string]struct{}
}

func LoadConfigs(jsonValue, filePath string) ([]Config, error) {
	jsonValue = strings.TrimSpace(jsonValue)
	filePath = strings.TrimSpace(filePath)
	if jsonValue != "" && filePath != "" {
		return nil, errors.New("настраивать только один NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON или NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_FILE")
	}
	if jsonValue == "" && filePath == "" {
		return nil, nil
	}
	raw := []byte(jsonValue)
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("чтение OIDC провайдеры файл: %w", err)
		}
		raw = data
	}
	var configs []Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode OIDC провайдеры конфигурация: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("OIDC провайдеры конфигурация содержит след JSON данные")
	}
	if len(configs) == 0 {
		return nil, errors.New("OIDC провайдеры конфигурация является пустой")
	}
	return configs, nil
}

func Normalize(input Config) (RuntimeConfig, error) {
	cfg := input
	cfg.ID = strings.ToLower(strings.TrimSpace(cfg.ID))
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.Issuer = strings.TrimSuffix(strings.TrimSpace(cfg.Issuer), "/")
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecretEnv = strings.TrimSpace(cfg.ClientSecretEnv)
	cfg.ClientSecretFile = strings.TrimSpace(cfg.ClientSecretFile)
	cfg.TokenEndpointAuthMethod = strings.ToLower(strings.TrimSpace(cfg.TokenEndpointAuthMethod))
	cfg.CAFile = strings.TrimSpace(cfg.CAFile)
	cfg.UserInfoMode = strings.ToLower(strings.TrimSpace(cfg.UserInfoMode))
	cfg.Provisioning.Mode = strings.ToLower(strings.TrimSpace(cfg.Provisioning.Mode))
	cfg.Provisioning.DefaultRole = strings.TrimSpace(cfg.Provisioning.DefaultRole)
	if err := validateProviderID(cfg.ID); err != nil {
		return RuntimeConfig{}, err
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	if len(cfg.DisplayName) > 128 {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: displayName exceeds 128 characters", cfg.ID)
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.User != nil {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: издатель должен быть absolute HTTPS URL без учётные данные, query или fragment", cfg.ID)
	}
	if cfg.ClientID == "" || len(cfg.ClientID) > 512 {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: clientId является обязательный и должен быть <= 512 байты", cfg.ID)
	}
	if cfg.TokenEndpointAuthMethod == "" {
		if cfg.ClientSecretEnv != "" || cfg.ClientSecretFile != "" {
			cfg.TokenEndpointAuthMethod = "client_secret_basic"
		} else {
			cfg.TokenEndpointAuthMethod = "none"
		}
	}
	switch cfg.TokenEndpointAuthMethod {
	case "client_secret_basic", "client_secret_post", "none":
	default:
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: неподдерживаемый tokenEndpointAuthMethod %q", cfg.ID, cfg.TokenEndpointAuthMethod)
	}
	if cfg.ClientSecretEnv != "" && cfg.ClientSecretFile != "" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: настраивать только один clientSecretEnv/clientSecretFile", cfg.ID)
	}
	secret := ""
	if cfg.ClientSecretEnv != "" {
		secret = os.Getenv(cfg.ClientSecretEnv)
		if secret == "" {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: переменная окружения %s является пустой", cfg.ID, cfg.ClientSecretEnv)
		}
	}
	if cfg.ClientSecretFile != "" {
		if !filepath.IsAbs(cfg.ClientSecretFile) {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: clientSecretFile должен быть absolute", cfg.ID)
		}
		b, err := os.ReadFile(cfg.ClientSecretFile)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: чтение клиент секрет: %w", cfg.ID, err)
		}
		secret = strings.TrimSpace(string(b))
	}
	if cfg.TokenEndpointAuthMethod != "none" && secret == "" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: клиент секрет является обязательный для %s", cfg.ID, cfg.TokenEndpointAuthMethod)
	}
	if cfg.TokenEndpointAuthMethod == "none" && secret != "" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: публичный клиент аутентификация метод none не может быть настраивать с клиент секрет", cfg.ID)
	}
	if len(cfg.RedirectURIs) == 0 {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: в least один redirectUri является обязательный", cfg.ID)
	}
	redirectSet := map[string]struct{}{}
	normalizedRedirects := make([]string, 0, len(cfg.RedirectURIs))
	for _, raw := range cfg.RedirectURIs {
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Fragment != "" {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: недопустимый redirectUri %q", cfg.ID, raw)
		}
		if u.Scheme == "http" {
			host := strings.ToLower(u.Hostname())
			if host != "127.0.0.1" && host != "::1" && host != "localhost" {
				return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: HTTP redirectUri является разрешён только для локальная петля клиенты", cfg.ID)
			}
		} else if u.Scheme != "https" && !strings.Contains(u.Scheme, ".") && !strings.Contains(u.Scheme, "+") && !strings.Contains(u.Scheme, "-") {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: redirectUri scheme %q является не разрешён", cfg.ID, u.Scheme)
		}
		if _, ok := redirectSet[raw]; !ok {
			redirectSet[raw] = struct{}{}
			normalizedRedirects = append(normalizedRedirects, raw)
		}
	}
	cfg.RedirectURIs = normalizedRedirects
	scopes := []string{"openid", "profile", "email"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}
	seenScope := map[string]struct{}{}
	cfg.Scopes = nil
	hasOpenID := false
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: недопустимый область", cfg.ID)
		}
		if scope == "openid" {
			hasOpenID = true
		}
		if _, ok := seenScope[scope]; !ok {
			seenScope[scope] = struct{}{}
			cfg.Scopes = append(cfg.Scopes, scope)
		}
	}
	if !hasOpenID {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: область должен включать openid", cfg.ID)
	}
	if len(cfg.HostAllowlist) == 0 {
		cfg.HostAllowlist = []string{strings.ToLower(issuer.Hostname())}
	}
	cfg.HostAllowlist, err = normalizeHosts(cfg.HostAllowlist)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: %w", cfg.ID, err)
	}
	if !hostAllowed(strings.ToLower(issuer.Hostname()), cfg.HostAllowlist) {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: издатель хост является не в hostAllowlist", cfg.ID)
	}
	allowedCIDRs := make([]*net.IPNet, 0, len(cfg.AllowedCIDRs))
	for _, raw := range cfg.AllowedCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: недопустимый allowedCidrs запись %q", cfg.ID, raw)
		}
		allowedCIDRs = append(allowedCIDRs, network)
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: caFile должен быть absolute", cfg.ID)
	}
	requestTimeout, err := parseDuration(cfg.RequestTimeout, 8*time.Second, time.Second, 30*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q requestTimeout: %w", cfg.ID, err)
	}
	connectTimeout, err := parseDuration(cfg.ConnectTimeout, 4*time.Second, 500*time.Millisecond, 15*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q connectTimeout: %w", cfg.ID, err)
	}
	skew, err := parseDuration(cfg.ClockSkew, 60*time.Second, 0, 5*time.Minute)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q clockSkew: %w", cfg.ID, err)
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 2 << 20
	}
	if cfg.MaxResponseBytes < 4096 || cfg.MaxResponseBytes > 8<<20 {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: maxResponseBytes должен быть 4096..8388608", cfg.ID)
	}
	if cfg.UserInfoMode == "" {
		cfg.UserInfoMode = "disabled"
	}
	if cfg.UserInfoMode != "disabled" && cfg.UserInfoMode != "optional" && cfg.UserInfoMode != "required" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: userInfoMode должен быть отключённый, необязательный или обязательный", cfg.ID)
	}
	mapping := &cfg.Claims
	if mapping.Subject == "" {
		mapping.Subject = "sub"
	}
	if mapping.Subject != "sub" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: захватывает.субъект должен быть standard OIDC sub захватывать", cfg.ID)
	}
	if mapping.Email == "" {
		mapping.Email = "email"
	}
	if mapping.Username == "" {
		mapping.Username = "preferred_username"
	}
	if mapping.DisplayName == "" {
		mapping.DisplayName = "name"
	}
	if mapping.Groups == "" {
		mapping.Groups = "groups"
	}
	if mapping.Roles == "" {
		mapping.Roles = "roles"
	}
	for _, item := range []string{mapping.Subject, mapping.Email, mapping.Username, mapping.DisplayName, mapping.Groups, mapping.Roles} {
		if err := validateClaimPath(item); err != nil {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: %w", cfg.ID, err)
		}
	}
	if len(cfg.RoleMappings) > 256 {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: слишком многие roleMappings", cfg.ID)
	}
	normalizedRoleMappings := make(map[string]string, len(cfg.RoleMappings))
	for externalValue, neverRole := range cfg.RoleMappings {
		externalValue = strings.TrimSpace(externalValue)
		neverRole = strings.TrimSpace(neverRole)
		if externalValue == "" || neverRole == "" || len(externalValue) > 256 || len(neverRole) > 128 {
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: недопустимый roleMappings запись", cfg.ID)
		}
		normalizedRoleMappings[externalValue] = neverRole
	}
	cfg.RoleMappings = normalizedRoleMappings

	if cfg.Provisioning.Mode == "" {
		cfg.Provisioning.Mode = "explicit-only"
	}
	if cfg.Provisioning.Mode != "explicit-only" && cfg.Provisioning.Mode != "jit" {
		return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: предоставление учётной записи.режим должен быть явный-только или jit", cfg.ID)
	}
	if cfg.Provisioning.Mode == "jit" && cfg.Provisioning.DefaultRole == "" {
		cfg.Provisioning.DefaultRole = "player"
	}
	algs := cfg.AllowedIDTokenAlgs
	if len(algs) == 0 {
		algs = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	algSet := map[string]struct{}{}
	cfg.AllowedIDTokenAlgs = nil
	for _, alg := range algs {
		alg = strings.TrimSpace(alg)
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		default:
			return RuntimeConfig{}, fmt.Errorf("OIDC коннектор %q: неподдерживаемый ID токен algorithm %q", cfg.ID, alg)
		}
		if _, ok := algSet[alg]; !ok {
			algSet[alg] = struct{}{}
			cfg.AllowedIDTokenAlgs = append(cfg.AllowedIDTokenAlgs, alg)
		}
	}
	return RuntimeConfig{Config: cfg, ParsedIssuer: issuer, ClientSecret: secret, RequestTimeoutValue: requestTimeout, ConnectTimeoutValue: connectTimeout, ClockSkewValue: skew, ParsedAllowedCIDRs: allowedCIDRs, redirectURISet: redirectSet, allowedIDTokenAlgSet: algSet}, nil
}

func (c RuntimeConfig) RedirectAllowed(v string) bool {
	_, ok := c.redirectURISet[strings.TrimSpace(v)]
	return ok
}
func (c RuntimeConfig) AlgAllowed(v string) bool { _, ok := c.allowedIDTokenAlgSet[v]; return ok }
func validateProviderID(v string) error {
	if v == "" {
		return errors.New("OIDC коннектор ID является обязательный")
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("недопустимый OIDC коннектор ID %q", v)
		}
	}
	return nil
}
func validateClaimPath(v string) error {
	if v == "" {
		return errors.New("захватывать сопоставление не может быть пустой")
	}
	if len(v) > 128 {
		return errors.New("захватывать сопоставление exceeds 128 байты")
	}
	for _, part := range strings.Split(v, ".") {
		if part == "" {
			return fmt.Errorf("недопустимый захватывать сопоставление %q", v)
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
				return fmt.Errorf("недопустимый захватывать сопоставление %q", v)
			}
		}
	}
	return nil
}
func normalizeHosts(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(v, ".")))
		if v == "" || strings.ContainsAny(v, "/@?#*") {
			return nil, fmt.Errorf("недопустимый hostAllowlist запись %q", v)
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out, nil
}
func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, v := range allowed {
		if host == v {
			return true
		}
	}
	return false
}
func parseDuration(raw string, def, min, max time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d < min || d > max {
		return 0, fmt.Errorf("должен быть между %s и %s", min, max)
	}
	return d, nil
}
