package conformance_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector/conformance"
)

type behaviorConnector struct {
	issuer, subject string
	revoked         bool
	swapped         bool
	password        string
}

func (c *behaviorConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "behavior", DisplayName: "Behavior fixture", Version: "2.0.0", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityTokenRefresh, authconnector.CapabilityTokenRevoke, authconnector.CapabilityUserLookup, authconnector.CapabilityProfile}}
}
func (c *behaviorConnector) Health(context.Context) error { return nil }
func (c *behaviorConnector) AuthenticatePassword(_ context.Context, r authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if r.Identifier != "test-user" || r.Secret != c.password {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Issuer: c.issuer, Subject: c.subject}, ProviderToken: "token-one", AuthMethods: []string{"password"}}, nil
}
func (c *behaviorConnector) ResolveIdentity(_ context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	return authconnector.Identity{Subject: req.Subject, Issuer: c.issuer}, nil
}
func (c *behaviorConnector) ResolveProfile(_ context.Context, req authconnector.ResolveRequest) (authconnector.Profile, error) {
	return authconnector.Profile{Subject: req.Subject}, nil
}
func (c *behaviorConnector) Refresh(_ context.Context, token string) (authconnector.Authentication, error) {
	if c.revoked || (token != "token-one" && token != "token-two") {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "rejected")
	}
	issuer := c.issuer
	if c.swapped {
		issuer = "issuer-other"
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Issuer: issuer, Subject: c.subject}, ProviderToken: "token-two"}, nil
}
func (c *behaviorConnector) Revoke(_ context.Context, r authconnector.RevokeRequest) error {
	if r.Subject != c.subject || r.ProviderToken != "token-two" {
		return errors.New("wrong token")
	}
	c.revoked = true
	return nil
}

func fixture() conformance.Fixture {
	return conformance.Fixture{Password: &authconnector.PasswordRequest{Identifier: "test-user", Secret: "only-test-password"}, Subject: "subject-1", Issuer: "issuer-1", AllowRevoke: true, VerifyRevokedToken: true}
}
func TestBehavioralConformanceExecutesEveryOperation(t *testing.T) {
	c := &behaviorConnector{issuer: "issuer-1", subject: "subject-1", password: "only-test-password"}
	report := conformance.RunBehavioral(context.Background(), c, fixture())
	if !report.Passed {
		t.Fatalf("failed: %+v", report)
	}
	if !c.revoked {
		t.Fatal("revoke executed")
	}
	required := map[string]bool{"registration": false, "health": false, "authenticate:password": false, "authenticate:wrong-password": false, "resolve:identity": false, "resolve:profile": false, "refresh": false, "revoke": false, "revoke:invalidation": false}
	for _, v := range report.Checks {
		if _, ok := required[v.Name]; ok {
			required[v.Name] = v.Passed
		}
	}
	for name, ok := range required {
		if !ok {
			t.Fatalf("required check %s not executed/passed", name)
		}
	}
}
func TestBehavioralConformanceFailsWithoutCredentials(t *testing.T) {
	c := &behaviorConnector{issuer: "issuer-1", subject: "subject-1", password: "only-test-password"}
	report := conformance.RunBehavioral(context.Background(), c, conformance.Fixture{})
	if report.Passed || c.revoked {
		t.Fatalf("missing fixture passed or revoked: %+v", report)
	}
}
func TestBehavioralConformanceRejectsIssuerSwapWithoutLoggingSecrets(t *testing.T) {
	c := &behaviorConnector{issuer: "issuer-1", subject: "subject-1", password: "only-test-password", swapped: true}
	report := conformance.RunBehavioral(context.Background(), c, fixture())
	if report.Passed {
		t.Fatalf("issuer swap passed: %+v", report)
	}
	for _, check := range report.Checks {
		if strings.Contains(check.Message, "only-test-password") || strings.Contains(check.Message, "token-one") || strings.Contains(check.Message, "token-two") {
			t.Fatalf("conformance leaked credentials: %+v", check)
		}
	}
}
func TestSDKRegistrationRejectsUndeclaredCredentialMethods(t *testing.T) {
	bad := undeclaredBehavior{&behaviorConnector{issuer: "issuer-1", subject: "subject-1"}}
	if err := authconnector.ValidateConnector(bad); err == nil {
		t.Fatal("undeclared methods accepted")
	}
}

type undeclaredBehavior struct{ *behaviorConnector }

func (c undeclaredBehavior) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "bad", DisplayName: "Bad", Version: "2", Capabilities: []authconnector.Capability{authconnector.CapabilityProfile}}
}

func TestSDKResponseValidations(t *testing.T) {
	for _, auth := range []authconnector.Authentication{
		{Identity: authconnector.Identity{}},
		{Identity: authconnector.Identity{Subject: "u"}, ProviderToken: strings.Repeat("x", 16385)},
		{Identity: authconnector.Identity{Subject: "u"}, AuthMethods: []string{""}},
	} {
		if authconnector.ValidateAuthentication(auth) == nil {
			t.Fatalf("invalid authentication accepted")
		}
	}
	if authconnector.ValidateAuthentication(authconnector.Authentication{Identity: authconnector.Identity{Subject: "u", Issuer: "issuer"}}) != nil {
		t.Fatal("valid identity rejected")
	}
	if authconnector.ValidateProfile(authconnector.Profile{Subject: "attacker"}, "user") == nil {
		t.Fatal("profile reassignment accepted")
	}
}
