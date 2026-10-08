package oidcconnector

import (
	"fmt"
	"strings"
)

// IssuerPolicy customizes issuer validation for standards-compatible providers
// whose discovery issuer is not a fixed literal. Generic OIDC uses ExactIssuerPolicy.
// Microsoft Entra tenant-independent metadata is the primary specialized consumer.
type IssuerPolicy interface {
	ValidateDiscoveryIssuer(configuredIssuer, discoveredIssuer string) error
	ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, signingKeyIssuer string) error
}

type ExactIssuerPolicy struct{}

func (ExactIssuerPolicy) ValidateDiscoveryIssuer(configuredIssuer, discoveredIssuer string) error {
	if strings.TrimSpace(discoveredIssuer) != strings.TrimSpace(configuredIssuer) {
		return fmt.Errorf("discovery issuer mismatch: got %q", discoveredIssuer)
	}
	return nil
}

func (ExactIssuerPolicy) ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, _ string) error {
	issuer, _ := claims["iss"].(string)
	if strings.TrimSpace(issuer) != strings.TrimSpace(discoveredIssuer) {
		return fmt.Errorf("ID token issuer mismatch")
	}
	return nil
}
