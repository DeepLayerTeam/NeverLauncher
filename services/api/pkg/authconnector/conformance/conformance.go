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

// Run performs executable SDK conformance checks. It intentionally does not invoke
// authentication with synthetic credentials; connector-specific integration tests
// remain responsible for credential fixtures.
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
			appendCheck("capability:password-auth", fmt.Errorf("advertised password-auth but PasswordAuthenticator is not implemented"))
		} else {
			appendCheck("capability:password-auth", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		if _, ok := connector.(authconnector.BrowserAuthenticator); !ok {
			appendCheck("capability:browser-auth", fmt.Errorf("advertised browser-auth but BrowserAuthenticator is not implemented"))
		} else {
			appendCheck("capability:browser-auth", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityProfile) {
		if _, ok := connector.(authconnector.ProfileResolver); !ok {
			appendCheck("capability:profile", fmt.Errorf("advertised profile but ProfileResolver is not implemented"))
		} else {
			appendCheck("capability:profile", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
		if _, ok := connector.(authconnector.TokenRefresher); !ok {
			appendCheck("capability:token-refresh", fmt.Errorf("advertised token-refresh but TokenRefresher is not implemented"))
		} else {
			appendCheck("capability:token-refresh", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRevoke) {
		if _, ok := connector.(authconnector.Revoker); !ok {
			appendCheck("capability:token-revoke", fmt.Errorf("advertised token-revoke but Revoker is not implemented"))
		} else {
			appendCheck("capability:token-revoke", nil)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityUserLookup) {
		if _, ok := connector.(authconnector.IdentityResolver); !ok {
			appendCheck("capability:user-lookup", fmt.Errorf("advertised user-lookup but IdentityResolver is not implemented"))
		} else {
			appendCheck("capability:user-lookup", nil)
		}
	}

	healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	appendCheck("health", connector.Health(healthCtx))
	return report
}
