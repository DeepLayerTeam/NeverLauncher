package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

var (
	ErrRoutingRequired = errors.New("explicit authentication provider required")
	ErrRoutingDenied   = errors.New("authentication provider denied by routing policy")
	ErrLinkingDisabled = errors.New("account linking disabled for provider")
)

// RoutingRule determines the sole eligible password provider for an exact email
// domain. Strict rules also reject manually supplied alternative providers.
// They never retry credentials with another backend.
type RoutingRule struct {
	EmailDomain string `json:"emailDomain"`
	ProviderID  string `json:"providerId"`
	Strict      bool   `json:"strict,omitempty"`
}

type RoutingConfig struct {
	Version                 int           `json:"version"`
	DefaultProvider         string        `json:"defaultProvider,omitempty"`
	RequireExplicitProvider bool          `json:"requireExplicitProvider,omitempty"`
	Rules                   []RoutingRule `json:"rules,omitempty"`
	// When specified, only these providers may be explicitly linked to an
	// existing, authenticated Never account after fresh provider proof.
	LinkingAllowProviders []string `json:"linkingAllowProviders,omitempty"`
	DisableLinking        bool     `json:"disableLinking,omitempty"`
}

var validRouteDomain0293 = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// LoadRoutingConfig limits configuration size and rejects unknown fields and
// trailing JSON objects. Empty configuration preserves the 0.29.2 local default.
func LoadRoutingConfig(jsonValue, filePath string) (RoutingConfig, error) {
	if strings.TrimSpace(jsonValue) != "" && strings.TrimSpace(filePath) != "" {
		return RoutingConfig{}, errors.New("configure only one of NEVERLAUNCHER_AUTH_ROUTING_JSON or NEVERLAUNCHER_AUTH_ROUTING_FILE")
	}
	var raw []byte
	if strings.TrimSpace(filePath) != "" {
		file, err := os.Open(strings.TrimSpace(filePath))
		if err != nil {
			return RoutingConfig{}, fmt.Errorf("open auth routing config: %w", err)
		}
		defer file.Close()
		raw, err = io.ReadAll(io.LimitReader(file, 65537))
		if err != nil {
			return RoutingConfig{}, err
		}
	} else {
		raw = []byte(strings.TrimSpace(jsonValue))
	}
	if len(raw) == 0 {
		return RoutingConfig{Version: 1, DefaultProvider: "local"}, nil
	}
	if len(raw) > 65536 {
		return RoutingConfig{}, errors.New("auth routing config exceeds 64 KiB")
	}
	if err := rejectDuplicateRoutingKeys0293(json.NewDecoder(strings.NewReader(string(raw)))); err != nil {
		return RoutingConfig{}, fmt.Errorf("ambiguous auth routing JSON: %w", err)
	}
	var cfg RoutingConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return RoutingConfig{}, fmt.Errorf("decode auth routing: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return RoutingConfig{}, errors.New("auth routing config must contain exactly one JSON object")
	}
	return cfg, nil
}

// rejectDuplicateRoutingKeys0293 recursively checks every object, including
// nested rules. Repeating a key must not silently override a strict route.
func rejectDuplicateRoutingKeys0293(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateRoutingKeys0293(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectDuplicateRoutingKeys0293(dec); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = dec.Token()
	return err
}

// ConfigureRouting validates all providers and atomically installs immutable
// routing decisions. A mistyped or missing provider prevents API startup.
func (c *Core) ConfigureRouting(cfg RoutingConfig) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported auth routing version %d", cfg.Version)
	}
	cfg.DefaultProvider = strings.ToLower(strings.TrimSpace(cfg.DefaultProvider))
	if cfg.DefaultProvider == "" && !cfg.RequireExplicitProvider {
		cfg.DefaultProvider = "local"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	eligible := func(id string) bool {
		conn, ok := c.connectors[id]
		return ok && authconnector.HasCapability(conn.Metadata(), authconnector.CapabilityPasswordAuth)
	}
	if cfg.DefaultProvider != "" && !eligible(cfg.DefaultProvider) {
		return fmt.Errorf("auth routing default provider %q is missing or cannot authenticate passwords", cfg.DefaultProvider)
	}
	rules := make([]RoutingRule, 0, len(cfg.Rules))
	domains := make(map[string]struct{}, len(cfg.Rules))
	if len(cfg.Rules) > 256 {
		return errors.New("auth routing exceeds 256 rules")
	}
	for _, rule := range cfg.Rules {
		rule.EmailDomain = strings.ToLower(strings.TrimSpace(rule.EmailDomain))
		rule.ProviderID = strings.ToLower(strings.TrimSpace(rule.ProviderID))
		if len(rule.EmailDomain) > 253 || !validRouteDomain0293.MatchString(rule.EmailDomain) {
			return fmt.Errorf("invalid auth routing email domain %q", rule.EmailDomain)
		}
		for _, label := range strings.Split(rule.EmailDomain, ".") {
			if len(label) > 63 {
				return fmt.Errorf("invalid auth routing email domain label in %q", rule.EmailDomain)
			}
		}
		if _, exists := domains[rule.EmailDomain]; exists {
			return fmt.Errorf("duplicate auth routing domain %q", rule.EmailDomain)
		}
		if !eligible(rule.ProviderID) {
			return fmt.Errorf("auth routing provider %q is missing or cannot authenticate passwords", rule.ProviderID)
		}
		domains[rule.EmailDomain] = struct{}{}
		rules = append(rules, rule)
	}
	if cfg.DisableLinking && len(cfg.LinkingAllowProviders) != 0 {
		return errors.New("disableLinking cannot be combined with linkingAllowProviders")
	}
	if len(cfg.LinkingAllowProviders) > 256 {
		return errors.New("auth linking allowlist exceeds 256 entries")
	}
	linking := make([]string, 0, len(cfg.LinkingAllowProviders))
	seen := map[string]bool{}
	for _, id := range cfg.LinkingAllowProviders {
		id = strings.ToLower(strings.TrimSpace(id))
		if _, exists := c.connectors[id]; !exists {
			return fmt.Errorf("auth linking provider %q not registered", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate auth linking provider %q", id)
		}
		seen[id] = true
		linking = append(linking, id)
	}
	cfg.Rules, cfg.LinkingAllowProviders = rules, linking
	c.routing = cfg
	return nil
}

// Routing returns a defensive copy of the live runtime configuration.
func (c *Core) Routing() RoutingConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg := c.routing
	cfg.Rules = append([]RoutingRule(nil), cfg.Rules...)
	cfg.LinkingAllowProviders = append([]string(nil), cfg.LinkingAllowProviders...)
	if cfg.Version == 0 {
		return RoutingConfig{Version: 1, DefaultProvider: "local"}
	}
	return cfg
}

func routeEmailDomain0293(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if strings.Count(identifier, "@") != 1 {
		return ""
	}
	at := strings.LastIndexByte(identifier, '@')
	if at < 1 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(identifier[at+1:]), ".")
}

// RoutePasswordProvider performs selection once. The caller must authenticate
// solely with the returned connector, propagating any failure unchanged.
func (c *Core) RoutePasswordProvider(requested, identifier string) (string, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	cfg := c.Routing()
	matched := RoutingRule{}
	domain := routeEmailDomain0293(identifier)
	for _, rule := range cfg.Rules {
		if rule.EmailDomain == domain {
			matched = rule
			break
		}
	}
	if requested == "" {
		if matched.ProviderID != "" {
			requested = matched.ProviderID
		} else if cfg.RequireExplicitProvider {
			return "", ErrRoutingRequired
		} else {
			requested = cfg.DefaultProvider
		}
	} else if matched.ProviderID != "" && matched.Strict && requested != matched.ProviderID {
		return "", ErrRoutingDenied
	}
	conn, exists := c.Connector(requested)
	if !exists {
		return "", ErrProviderNotFound
	}
	if !authconnector.HasCapability(conn.Metadata(), authconnector.CapabilityPasswordAuth) {
		return "", ErrCapabilityUnsupported
	}
	return requested, nil
}

// EnsureLinkAllowed applies the configured provider allowlist for both browser
// and password linking, without using unverified email claims for linkage.
func (c *Core) EnsureLinkAllowed(providerID string) error {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	c.mu.RLock()
	_, exists := c.connectors[providerID]
	cfg := c.routing
	c.mu.RUnlock()
	if !exists {
		return ErrProviderNotFound
	}
	if cfg.DisableLinking {
		return ErrLinkingDisabled
	}
	if len(cfg.LinkingAllowProviders) == 0 {
		return nil
	}
	for _, allowed := range cfg.LinkingAllowProviders {
		if allowed == providerID {
			return nil
		}
	}
	return ErrLinkingDisabled
}
