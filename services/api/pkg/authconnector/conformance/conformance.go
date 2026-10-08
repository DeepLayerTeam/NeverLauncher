package conformance

import (
	"context"
	"fmt"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type Report struct {
	ConnectorID string  `json:"connectorId"`
	Passed      bool    `json:"passed"`
	Checks      []Check `json:"checks"`
}

// Запуск выполняет исполняемый SDK соответствие проверяет. Это намеренно делает не invoke
// аутентификация с synthetic учётные данные; коннектор-specific интеграционные тесты
// оставаться responsible для учётные данные фикстура.
func Run(ctx context.Context, connector authconnector.Connector) Report {
	report := Report{Passed: true}
	if connector == nil {
		return Report{Passed: false, Checks: []Check{{Name: "connector", Passed: false, Message: "connector is nil"}}}
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	report.ConnectorID = meta.ID
	appendCheck := func(name string, err error) {
		check := Check{Name: name, Passed: err == nil}
		if err != nil {
			check.Message = err.Error()
			report.Passed = false
		}
		report.Checks = append(report.Checks, check)
	}
	appendCheck("metadata", authconnector.ValidateMetadata(meta))

	if authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) {
		if _, ok := connector.(authconnector.PasswordAuthenticator); !ok {
			appendCheck("capability:password-auth", fmt.Errorf("advertised пароль-аутентификация но PasswordAuthenticator является не implemented"))
		} else {
			appendCheck("capability:password-auth", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		if _, ok := connector.(authconnector.BrowserAuthenticator); !ok {
			appendCheck("capability:browser-auth", fmt.Errorf("advertised browser-аутентификация но BrowserAuthenticator является не implemented"))
		} else {
			appendCheck("capability:browser-auth", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityProfile) {
		if _, ok := connector.(authconnector.ProfileResolver); !ok {
			appendCheck("capability:profile", fmt.Errorf("advertised профиль но ProfileResolver является не implemented"))
		} else {
			appendCheck("capability:profile", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
		if _, ok := connector.(authconnector.TokenRefresher); !ok {
			appendCheck("capability:token-refresh", fmt.Errorf("advertised токен-обновление но TokenRefresher является не implemented"))
		} else {
			appendCheck("capability:token-refresh", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRevoke) {
		if _, ok := connector.(authconnector.Revoker); !ok {
			appendCheck("capability:token-revoke", fmt.Errorf("advertised токен-отзыв но Revoker является не implemented"))
		} else {
			appendCheck("capability:token-revoke", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityUserLookup) {
		if _, ok := connector.(authconnector.IdentityResolver); !ok {
			appendCheck("capability:user-lookup", fmt.Errorf("advertised пользователь-поиск но IdentityResolver является не implemented"))
		} else {
			appendCheck("capability:user-lookup", nil)
		}
	}

	healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	appendCheck("health", connector.Health(healthCtx))
	return report
}
