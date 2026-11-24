package oidcconnector

import (
	"fmt"
	"strings"
)

// WithSkif4erID registers the dedicated public desktop client. The issuer,
// redirect and role policy are fixed, not supplied by a desktop request.
func WithSkif4erID(configs []Config, clientID string) ([]Config, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return configs, nil
	}
	for _, cfg := range configs {
		if strings.EqualFold(strings.TrimSpace(cfg.ID), "skif4er-id") {
			return nil, fmt.Errorf("SkiF4er ID: duplicate provider registration")
		}
	}
	cfg := Config{ID: "skif4er-id", DisplayName: "SkiF4er ID", Issuer: "https://id.skif4er.ru/realms/skif4er", ClientID: clientID,
		TokenEndpointAuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1:8765/callback"},
		Scopes: []string{"openid", "profile", "email"}, HostAllowlist: []string{"id.skif4er.ru"},
		AllowedIDTokenAlgs: []string{"RS256"}, RequireVerifiedEmail: true, UserInfoMode: "required",
		Provisioning: ProvisioningConfig{Mode: "jit", DefaultRole: "player"}}
	if _, err := Normalize(cfg); err != nil {
		return nil, err
	}
	return append(configs, cfg), nil
}
