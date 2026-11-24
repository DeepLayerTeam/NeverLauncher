package oidcconnector

import (
	"fmt"
	"net/url"
	"strings"
)

// WithSkif4erID registers the dedicated public desktop client. The issuer,
// redirect and role policy are fixed, not supplied by a desktop request.
func WithSkif4erID(configs []Config, clientID string, adminRedirect ...string) ([]Config, error) {
	clientID = strings.TrimSpace(clientID)
	redirects := []string{"http://127.0.0.1:8765/callback"}
	for _, raw := range adminRedirect {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/auth/skif4er/callback" || u.RawPath != "" || strings.Contains(raw, "*") {
			return nil, fmt.Errorf("SkiF4er ID: invalid Admin HTTPS callback URI")
		}
		redirects = append(redirects, raw)
	}
	if clientID == "" {
		if len(redirects) > 1 {
			return nil, fmt.Errorf("SkiF4er ID: Admin callback requires client ID")
		}
		return configs, nil
	}
	for _, cfg := range configs {
		if strings.EqualFold(strings.TrimSpace(cfg.ID), "skif4er-id") {
			return nil, fmt.Errorf("SkiF4er ID: duplicate provider registration")
		}
	}
	cfg := Config{ID: "skif4er-id", DisplayName: "SkiF4er ID", Issuer: "https://id.skif4er.ru/realms/skif4er", ClientID: clientID,
		TokenEndpointAuthMethod: "none", RedirectURIs: redirects,
		Scopes: []string{"openid", "profile", "email"}, HostAllowlist: []string{"id.skif4er.ru"},
		AllowedIDTokenAlgs: []string{"RS256"}, RequireVerifiedEmail: true, UserInfoMode: "required",
		Provisioning: ProvisioningConfig{Mode: "jit", DefaultRole: "player"}}
	if _, err := Normalize(cfg); err != nil {
		return nil, err
	}
	return append(configs, cfg), nil
}
