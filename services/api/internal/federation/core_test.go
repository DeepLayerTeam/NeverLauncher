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
