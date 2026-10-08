package oidcconnector

import (
	"fmt"
	"strings"
)

// IssuerPolicy customizes издатель валидация для standards-compatible провайдеры
// чей обнаружение издатель является не фиксированный literal. Общий OIDC использует ExactIssuerPolicy.
// Microsoft Entra tenant-независимый метаданные является primary specialized consumer.
type IssuerPolicy interface {
	ValidateDiscoveryIssuer(configuredIssuer, discoveredIssuer string) error
	ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, signingKeyIssuer string) error
}

type ExactIssuerPolicy struct{}

func (ExactIssuerPolicy) ValidateDiscoveryIssuer(configuredIssuer, discoveredIssuer string) error {
	if strings.TrimSpace(discoveredIssuer) != strings.TrimSpace(configuredIssuer) {
		return fmt.Errorf("обнаружение издатель несоответствие: получил %q", discoveredIssuer)
	}
	return nil
}

func (ExactIssuerPolicy) ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, _ string) error {
	issuer, _ := claims["iss"].(string)
	if strings.TrimSpace(issuer) != strings.TrimSpace(discoveredIssuer) {
		return fmt.Errorf("ID токен издатель несоответствие")
	}
	return nil
}
