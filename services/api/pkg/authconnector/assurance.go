package authconnector

import "strings"

// SafeUpstreamAuthMethods записывает методы аутентификации, заявленные
// внешним провайдером, не повышая их до локально подтверждённого
// Launcher MFA. Перед добавлением таких методов и повышением authStrength вызывающий ОБЯЗАН отдельно проверить
// локальный TOTP/recovery или утверждение WebAuthn.
// В частности, подписанные HTTP-данные провайдера и проверенные OIDC amr-claims являются
// пока остаются заявлениями внешнего провайдера, а не доказательствами Launcher WebAuthn.
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
			// Они определяют только вышестоящий протокол или первичный фактор.
		default:
			method = "upstream:" + method
		}
		// Заявления токена сеанса должны укладываться в лимит полей SDK, даже
		// если провайдер передал максимально допустимое 64-байтное имя amr.
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
