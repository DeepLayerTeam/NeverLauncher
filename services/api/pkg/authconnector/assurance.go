package authconnector

import "strings"

// SafeUpstreamAuthMethods records the authentication methods claimed by an
// external provider without promoting those claims to locally verified
// Launcher MFA. Callers MUST separately verify local TOTP/recovery or a
// WebAuthn assertion before adding those methods and increasing authStrength.
// In particular, signed HTTP provider data and validated OIDC amr claims are
// still upstream statements, not Launcher WebAuthn proofs.
func SafeUpstreamAuthMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))
	for _, raw := range methods {
		method := strings.ToLower(strings.TrimSpace(raw))
		if method == "" {
			continue
		}
		switch method {
		case "password", "pwd", "oidc", "microsoft", "oauth", "sql", "http", "local":
			// These identify an upstream protocol or primary factor only.
		default:
			method = "upstream:" + method
		}
		// Session token claims must remain within the SDK field limit even
		// when a provider supplies the maximum permitted 64-byte amr name.
		if len(method) > 64 {
			method = method[:64]
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out
}
