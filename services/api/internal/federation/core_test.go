package federation

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type fixtureConnector struct{}

func (fixtureConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "local", DisplayName: "Local", Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityEmail}}
}
func (fixtureConnector) Health(context.Context) error { return nil }
func (fixtureConnector) AuthenticatePassword(context.Context, authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "admin", Email: "admin@neverlauncher.local"}, AuthMethods: []string{"password"}}, nil
}

func TestAuthenticatePasswordResolvesCanonicalUser(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	core := New(repo)
	if err := core.Register(fixtureConnector{}); err != nil {
		t.Fatal(err)
	}
	result, err := core.AuthenticatePassword(context.Background(), "local", authconnector.PasswordRequest{Identifier: "admin@neverlauncher.local", Secret: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.ID != "admin" || result.Identity.Provider != "local" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.AuthMethods) != 1 || result.AuthMethods[0] != "password" {
		t.Fatalf("auth methods lost: %+v", result.AuthMethods)
	}
}

type unlinkedConnector struct{ fixtureConnector }

func (unlinkedConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "external", DisplayName: "External", Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (unlinkedConnector) AuthenticatePassword(context.Context, authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "external-42"}}, nil
}
func TestAuthenticateRejectsUnlinkedIdentity(t *testing.T) {
	core := New(repository.NewMemoryRepository("http://example.test"))
	_ = core.Register(unlinkedConnector{})
	if _, err := core.AuthenticatePassword(context.Background(), "external", authconnector.PasswordRequest{}); err != ErrIdentityNotLinked {
		t.Fatalf("got %v", err)
	}
}

func TestLinkAuthenticatedIdentityRejectsReassignment(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	second, err := repo.SaveUser(model.User{Email: "second@example.test", DisplayName: "Second", RoleID: "viewer", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	core := New(repo)
	if err := core.Register(unlinkedConnector{}); err != nil {
		t.Fatal(err)
	}
	proof := authconnector.Authentication{Identity: authconnector.Identity{Subject: "external-42", Email: "external@example.test"}}
	if _, err := core.LinkAuthenticatedIdentity("admin", "external", proof); err != nil {
		t.Fatal(err)
	}
	if _, err := core.LinkAuthenticatedIdentity(second.ID, "external", proof); authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
}

type jitFixtureConnector struct{}

func (jitFixtureConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "website", DisplayName: "Website SQL", Version: "0.11.3", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityEmail}}
}
func (jitFixtureConnector) Health(context.Context) error { return nil }
func (jitFixtureConnector) AuthenticatePassword(context.Context, authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: "42", Email: "player@example.test", Username: "player", DisplayName: "Player 42", Claims: map[string]any{"groups": []string{"vip"}}}, AuthMethods: []string{"password"}}, nil
}

func TestAuthenticatePasswordJITProvisionsCanonicalUser(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	core := New(repo)
	if err := core.RegisterWithPolicy(jitFixtureConnector{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	result, err := core.AuthenticatePassword(context.Background(), "website", authconnector.PasswordRequest{Identifier: "player", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.RoleID != "player" || result.Identity.Provider != "website" || result.Identity.Subject != "42" {
		t.Fatalf("unexpected JIT result: %+v", result)
	}
	if result.User.PasswordHash != "" {
		t.Fatal("JIT federated user unexpectedly has a local password")
	}
	if _, err := repo.GetAuthIdentity("local", result.User.ID); err == nil {
		t.Fatal("JIT federated user unexpectedly received local identity")
	}
	again, err := core.AuthenticatePassword(context.Background(), "website", authconnector.PasswordRequest{Identifier: "player", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if again.User.ID != result.User.ID {
		t.Fatalf("JIT user id is not stable: %s != %s", again.User.ID, result.User.ID)
	}
}

func TestJITProvisioningDoesNotAutoLinkMatchingEmail(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	if _, err := repo.SaveUser(model.User{ID: "existing", Email: "player@example.test", DisplayName: "Existing", RoleID: "player", Status: "active", PasswordHash: "sha256:deadbeef"}); err != nil {
		t.Fatal(err)
	}
	core := New(repo)
	if err := core.RegisterWithPolicy(jitFixtureConnector{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	_, err := core.AuthenticatePassword(context.Background(), "website", authconnector.PasswordRequest{Identifier: "player", Secret: "secret"})
	if authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("expected explicit-link conflict, got %v", err)
	}
	if _, err := repo.GetAuthIdentity("website", "42"); err == nil {
		t.Fatal("matching email silently linked external identity")
	}
}
