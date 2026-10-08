package httpconnector

import (
	"bytes"
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

const (
	providerVersion = "0.11.4"
	protocolVersion = "neverlauncher-http-auth/1"
)

type EndpointConfig struct {
	Authenticate string `json:"authenticate,omitempty"`
	Refresh      string `json:"refresh,omitempty"`
	Resolve      string `json:"resolve,omitempty"`
	Logout       string `json:"logout,omitempty"`
	Health       string `json:"health,omitempty"`
}

type HMACConfig struct {
	KeyID        string `json:"keyId,omitempty"`
	SecretEnv    string `json:"secretEnv,omitempty"`
	SecretFile   string `json:"secretFile,omitempty"`
	MaxClockSkew string `json:"maxClockSkew,omitempty"`
}

type MTLSConfig struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	CAFile   string `json:"caFile,omitempty"`
}

type ProvisioningConfig struct {
	Mode        string `json:"mode,omitempty"`
	DefaultRole string `json:"defaultRole,omitempty"`
}

type Config struct {
	ID               string             `json:"id"`
	DisplayName      string             `json:"displayName,omitempty"`
	BaseURL          string             `json:"baseUrl"`
	Issuer           string             `json:"issuer"`
	HostAllowlist    []string           `json:"hostAllowlist,omitempty"`
	AllowedCIDRs     []string           `json:"allowedCidrs,omitempty"`
	Endpoints        EndpointConfig     `json:"endpoints,omitempty"`
	HMAC             HMACConfig         `json:"hmac"`
	MTLS             MTLSConfig         `json:"mtls,omitempty"`
	RequestTimeout   string             `json:"requestTimeout,omitempty"`
	ConnectTimeout   string             `json:"connectTimeout,omitempty"`
	MaxResponseBytes int64              `json:"maxResponseBytes,omitempty"`
	MaxIdleConns     int                `json:"maxIdleConns,omitempty"`
	MaxConnsPerHost  int                `json:"maxConnsPerHost,omitempty"`
	IdleConnTimeout  string             `json:"idleConnTimeout,omitempty"`
	Provisioning     ProvisioningConfig `json:"provisioning,omitempty"`
}

type RuntimeConfig struct {
	Config
	ParsedBaseURL           *url.URL
	HMACSecret              []byte
	MaxClockSkewDuration    time.Duration
	RequestTimeoutDuration  time.Duration
	ConnectTimeoutDuration  time.Duration
	IdleConnTimeoutDuration time.Duration
	ParsedAllowedCIDRs      []*net.IPNet
}

func LoadConfigs(jsonValue, filePath string) ([]Config, error) {
	jsonValue = strings.TrimSpace(jsonValue)
	filePath = strings.TrimSpace(filePath)
	if jsonValue != "" && filePath != "" {
		return nil, errors.New("настраивать только один NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON или NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE")
	}
	if jsonValue == "" && filePath == "" {
		return nil, nil
	}
	raw := []byte(jsonValue)
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("чтение HTTP аутентификация провайдеры файл: %w", err)
		}
		raw = data
	}
	var configs []Config
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode HTTP аутентификация провайдеры конфигурация: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("HTTP аутентификация провайдеры конфигурация содержит след JSON данные")
	}
	if len(configs) == 0 {
		return nil, errors.New("HTTP аутентификация провайдеры конфигурация является пустой")
	}
	return configs, nil
}

func Normalize(input Config) (RuntimeConfig, error) {
	cfg := input
	cfg.ID = strings.ToLower(strings.TrimSpace(cfg.ID))
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.HMAC.KeyID = strings.TrimSpace(cfg.HMAC.KeyID)
	cfg.HMAC.SecretEnv = strings.TrimSpace(cfg.HMAC.SecretEnv)
	cfg.HMAC.SecretFile = strings.TrimSpace(cfg.HMAC.SecretFile)
	cfg.MTLS.CertFile = strings.TrimSpace(cfg.MTLS.CertFile)
	cfg.MTLS.KeyFile = strings.TrimSpace(cfg.MTLS.KeyFile)
	cfg.MTLS.CAFile = strings.TrimSpace(cfg.MTLS.CAFile)
	cfg.Provisioning.Mode = strings.ToLower(strings.TrimSpace(cfg.Provisioning.Mode))
	cfg.Provisioning.DefaultRole = strings.TrimSpace(cfg.Provisioning.DefaultRole)

	if err := validateProviderID(cfg.ID); err != nil {
		return RuntimeConfig{}, err
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	if len(cfg.DisplayName) > 128 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: displayName exceeds 128 characters", cfg.ID)
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: baseUrl должен быть absolute HTTPS URL", cfg.ID)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: baseUrl не может contain учётные данные, query или fragment", cfg.ID)
	}
	if parsed.Port() != "" {
		if _, err := net.LookupPort("tcp", parsed.Port()); err != nil {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: недопустимый baseUrl port: %w", cfg.ID, err)
		}
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	if cfg.Issuer == "" || len(cfg.Issuer) > 256 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: издатель является обязательный и должен быть <= 256 characters", cfg.ID)
	}

	host := strings.ToLower(parsed.Hostname())
	if len(cfg.HostAllowlist) == 0 {
		cfg.HostAllowlist = []string{host}
	}
	seenHosts := map[string]struct{}{}
	normalizedHosts := make([]string, 0, len(cfg.HostAllowlist))
	for _, item := range cfg.HostAllowlist {
		item = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(item, ".")))
		if item == "" || strings.ContainsAny(item, "/@?#*") {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: недопустимый hostAllowlist запись %q", cfg.ID, item)
		}
		if net.ParseIP(item) == nil {
			for _, r := range item {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
					return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: недопустимый hostAllowlist запись %q", cfg.ID, item)
				}
			}
		}
		if _, ok := seenHosts[item]; ok {
			continue
		}
		seenHosts[item] = struct{}{}
		normalizedHosts = append(normalizedHosts, item)
	}
	cfg.HostAllowlist = normalizedHosts
	if !hostAllowed(host, cfg.HostAllowlist) {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: baseUrl хост %q является не в hostAllowlist", cfg.ID, host)
	}

	allowedCIDRs := make([]*net.IPNet, 0, len(cfg.AllowedCIDRs))
	for _, raw := range cfg.AllowedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: недопустимый allowedCidrs запись %q: %w", cfg.ID, raw, err)
		}
		allowedCIDRs = append(allowedCIDRs, network)
	}

	if cfg.Endpoints.Authenticate == "" {
		cfg.Endpoints.Authenticate = "/authenticate"
	}
	if cfg.Endpoints.Refresh == "" {
		cfg.Endpoints.Refresh = "/refresh"
	}
	if cfg.Endpoints.Resolve == "" {
		cfg.Endpoints.Resolve = "/resolve"
	}
	if cfg.Endpoints.Logout == "" {
		cfg.Endpoints.Logout = "/logout"
	}
	if cfg.Endpoints.Health == "" {
		cfg.Endpoints.Health = "/health"
	}
	for name, endpoint := range map[string]string{
		"authenticate": cfg.Endpoints.Authenticate, "refresh": cfg.Endpoints.Refresh,
		"resolve": cfg.Endpoints.Resolve, "logout": cfg.Endpoints.Logout, "health": cfg.Endpoints.Health,
	} {
		if err := validateEndpointPath(endpoint); err != nil {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q эндпоинт %s: %w", cfg.ID, name, err)
		}
	}

	secret, err := loadHMACSecret(cfg.HMAC)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: %w", cfg.ID, err)
	}
	if len(secret) < 32 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: HMAC секрет должен contain в least 32 байты", cfg.ID)
	}
	if cfg.HMAC.KeyID == "" {
		cfg.HMAC.KeyID = cfg.ID
	}
	if len(cfg.HMAC.KeyID) > 128 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: HMAC keyId exceeds 128 characters", cfg.ID)
	}
	for _, r := range cfg.HMAC.KeyID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: HMAC keyId содержит неподдерживаемый character %q", cfg.ID, r)
		}
	}

	if (cfg.MTLS.CertFile == "") != (cfg.MTLS.KeyFile == "") {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: mTLS certFile и keyFile должен быть настраивать together", cfg.ID)
	}
	for label, path := range map[string]string{"certFile": cfg.MTLS.CertFile, "keyFile": cfg.MTLS.KeyFile, "caFile": cfg.MTLS.CAFile} {
		if path != "" && !filepath.IsAbs(path) {
			return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: mTLS %s должен быть absolute путь", cfg.ID, label)
		}
	}

	maxSkew, err := parseDuration(cfg.HMAC.MaxClockSkew, 2*time.Minute, 5*time.Second, 10*time.Minute)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q HMAC.maxClockSkew: %w", cfg.ID, err)
	}
	requestTimeout, err := parseDuration(cfg.RequestTimeout, 5*time.Second, 250*time.Millisecond, 30*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q requestTimeout: %w", cfg.ID, err)
	}
	connectTimeout, err := parseDuration(cfg.ConnectTimeout, 3*time.Second, 100*time.Millisecond, 15*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q connectTimeout: %w", cfg.ID, err)
	}
	idleTimeout, err := parseDuration(cfg.IdleConnTimeout, 45*time.Second, time.Second, 5*time.Minute)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q idleConnTimeout: %w", cfg.ID, err)
	}

	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 8<<20 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: maxResponseBytes должен быть между 1024 и 8388608", cfg.ID)
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 16
	}
	if cfg.MaxIdleConns < 1 || cfg.MaxIdleConns > 256 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: maxIdleConns должен быть между 1 и 256", cfg.ID)
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = 32
	}
	if cfg.MaxConnsPerHost < 1 || cfg.MaxConnsPerHost > 256 {
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: maxConnsPerHost должен быть между 1 и 256", cfg.ID)
	}

	if cfg.Provisioning.Mode == "" {
		cfg.Provisioning.Mode = "jit"
	}
	switch cfg.Provisioning.Mode {
	case "jit", "explicit-only":
	default:
		return RuntimeConfig{}, fmt.Errorf("HTTP коннектор %q: неподдерживаемый предоставление учётной записи режим %q", cfg.ID, cfg.Provisioning.Mode)
	}
	if cfg.Provisioning.DefaultRole == "" {
		cfg.Provisioning.DefaultRole = "player"
	}

	return RuntimeConfig{
		Config: cfg, ParsedBaseURL: parsed, HMACSecret: secret,
		MaxClockSkewDuration: maxSkew, RequestTimeoutDuration: requestTimeout,
		ConnectTimeoutDuration: connectTimeout, IdleConnTimeoutDuration: idleTimeout,
		ParsedAllowedCIDRs: allowedCIDRs,
	}, nil
}

func validateProviderID(id string) error {
	if id == "" || id == "local" {
		return errors.New("HTTP коннектор ID является обязательный и не может быть 'local'")
	}
	if len(id) > 64 {
		return fmt.Errorf("HTTP коннектор ID %q exceeds 64 characters", id)
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("HTTP коннектор ID %q содержит неподдерживаемый character %q", id, r)
		}
	}
	return nil
}

func validateEndpointPath(value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return errors.New("должен быть absolute путь beginning с один slash")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("должен быть relative эндпоинт путь без хост, query или fragment")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == ".." || segment == "." {
			return errors.New("обход путей segments являются не разрешён")
		}
	}
	return nil
}

func loadHMACSecret(cfg HMACConfig) ([]byte, error) {
	if (cfg.SecretEnv == "") == (cfg.SecretFile == "") {
		return nil, errors.New("настраивать точно один HMAC.secretEnv или HMAC.secretFile")
	}
	var raw []byte
	if cfg.SecretEnv != "" {
		value, ok := os.LookupEnv(cfg.SecretEnv)
		if !ok || value == "" {
			return nil, fmt.Errorf("HMAC секрет переменная окружения %s является пустой", cfg.SecretEnv)
		}
		raw = []byte(value)
	} else {
		data, err := os.ReadFile(cfg.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("чтение HMAC секрет файл: %w", err)
		}
		raw = bytes.TrimSuffix(data, []byte("\r\n"))
		raw = bytes.TrimSuffix(raw, []byte("\n"))
	}
	return append([]byte(nil), raw...), nil
}

func parseDuration(raw string, fallback, min, max time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if value < min || value > max {
		return 0, fmt.Errorf("duration должен быть между %s и %s", min, max)
	}
	return value, nil
}

func hostAllowed(host string, allowlist []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, allowed := range allowlist {
		if host == strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowed), ".")) {
			return true
		}
	}
	return false
}
