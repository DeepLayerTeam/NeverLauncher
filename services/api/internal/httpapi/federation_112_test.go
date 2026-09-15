package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector/conformance"
)

func TestLocalConnector112Conformance(t *testing.T) {
	connector := localAuthConnector112{repo: repository.NewMemoryRepository("http://example.test")}
	report := conformance.Run(context.Background(), connector)
	if !report.Passed {
		t.Fatalf("local connector failed conformance: %+v", report)
	}
}

type externalFixtureConnector112 struct{}

func (externalFixtureConnector112) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "fixture", DisplayName: "Fixture Provider", Version: "1.0.0", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (externalFixtureConnector112) Health(context.Context) error { return nil }
func (externalFixtureConnector112) AuthenticatePassword(context.Context, authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "fixture-subject", Email: "external@example.test", DisplayName: "External Admin"}, AuthMethods: []string{"password"}, ProviderToken: "provider-secret-must-not-leak"}, nil
}

func TestHTTPLoginUsesRegisteredExternalConnector112(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	if _, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "fixture", Subject: "fixture-subject"}); err != nil {
		t.Fatal(err)
	}
	core, err := NewFederationCore112(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Register(externalFixtureConnector112{}); err != nil {
		t.Fatal(err)
	}

	api := Server{
		Version:    "0.11.2-test",
		Config:     config.Config{Environment: "test", RepositoryDriver: "memory", AuthTokenSecret: "federation-test-secret"},
		Repo:       repo,
		State:      NewRuntimeState(),
		Federation: core,
	}
	handler := api.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"identifier":"anything","password":"secret","providerId":"fixture"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"provider":"fixture"`) || !strings.Contains(res.Body.String(), `"id":"admin"`) {
		t.Fatalf("external connector login returned %d: %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "provider-secret-must-not-leak") {
		t.Fatalf("provider token leaked into Never auth response: %s", res.Body.String())
	}
}
