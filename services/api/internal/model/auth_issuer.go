package model

import (
	"errors"
	"strings"
	"unicode"
)

// CanonicalAuthIssuer сохраняет точный проверенный внешний issuer: OIDC iss
// чувствителен к регистру. Коннектор без issuer на уровне протокола помещается в
// пространство имён своего provider ID. Это пространство имён НЕ является независимо
// проверенным OIDC issuer.
func CanonicalAuthIssuer(provider, issuer string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || len(provider) > 128 || strings.IndexFunc(provider, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("invalid auth provider")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		if provider == "local" {
			issuer = "launcher"
		} else {
			issuer = "provider:" + provider
		}
	}
	if len(issuer) > 2048 || strings.IndexFunc(issuer, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("invalid auth issuer")
	}
	if provider == "local" && issuer != "launcher" {
		return "", errors.New("local provider cannot change issuer")
	}
	return issuer, nil
}
