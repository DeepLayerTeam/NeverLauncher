package model

import (
	"errors"
	"strings"
	"unicode"
)

// CanonicalAuthIssuer retains the exact, verified external issuer (OIDC iss is
// case-sensitive). A connector without a protocol-level issuer is namespaced by
// its provider ID. This namespace is NOT an independently verified OIDC issuer.
func CanonicalAuthIssuer(provider, issuer string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || len(provider) > 128 || strings.IndexFunc(provider, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("invalid auth provider")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		if provider == "local" {
			issuer = "neverlauncher"
		} else {
			issuer = "provider:" + provider
		}
	}
	if len(issuer) > 2048 || strings.IndexFunc(issuer, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("invalid auth issuer")
	}
	if provider == "local" && issuer != "neverlauncher" {
		return "", errors.New("local provider cannot change issuer")
	}
	return issuer, nil
}
