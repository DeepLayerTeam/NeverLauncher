package authconnector_test

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector/conformance"
)

type goodConnector struct{}

func (goodConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "fixture", DisplayName: "Fixture", Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (goodConnector) Health(context.Context) error { return nil }
func (goodConnector) AuthenticatePassword(context.Context, authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "user-1"}}, nil
}

type brokenConnector struct{ goodConnector }

func (brokenConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "broken", DisplayName: "Broken", Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityTokenRefresh}}
}

func TestConformanceChecksCapabilityInterfaces(t *testing.T) {
	if report := conformance.Run(context.Background(), goodConnector{}); !report.Passed {
		t.Fatalf("good connector failed conformance: %+v", report)
	}
	if report := conformance.Run(context.Background(), brokenConnector{}); report.Passed {
		t.Fatalf("broken connector unexpectedly passed: %+v", report)
	}
}
