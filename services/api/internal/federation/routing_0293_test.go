package federation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type routingConnector0293 struct {
	id     string
	issuer string
	fail   bool
	calls  *int
}

func (f routingConnector0293) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: f.id, DisplayName: f.id, Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (f routingConnector0293) Health(context.Context) error { return nil }
func (f routingConnector0293) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	*f.calls++
	if f.fail || req.Secret != "verified" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "denied")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Issuer: f.issuer, Subject: "42", Email: "same@enterprise.test"}, AuthMethods: []string{"password"}}, nil
}

func TestRouting0293ExactDomainSelectionAndNoFallback(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core := New(repo)
	primaryCalls, fallbackCalls := 0, 0
	for _, c := range []routingConnector0293{{id: "primary", issuer: "https://one.test", fail: true, calls: &primaryCalls}, {id: "fallback", issuer: "https://two.test", calls: &fallbackCalls}} {
		if err := core.RegisterWithPolicy(c, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := RoutingConfig{Version: 1, DefaultProvider: "fallback", Rules: []RoutingRule{{EmailDomain: "enterprise.test", ProviderID: "primary", Strict: true}}}
	if err := core.ConfigureRouting(cfg); err != nil {
		t.Fatal(err)
	}
	selected, err := core.RoutePasswordProvider("", "  user@ENTERPRISE.TEST  ")
	if err != nil || selected != "primary" {
		t.Fatalf("domain routing: %q %v", selected, err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "", authconnector.PasswordRequest{Identifier: "user@enterprise.test", Secret: "verified"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("unexpected primary error: %v", err)
	}
	if primaryCalls != 1 || fallbackCalls != 0 {
		t.Fatalf("provider fallback occurred: primary=%d fallback=%d", primaryCalls, fallbackCalls)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "fallback", authconnector.PasswordRequest{Identifier: "user@enterprise.test", Secret: "verified"}); !errors.Is(err, ErrRoutingDenied) {
		t.Fatalf("strict route bypass: %v", err)
	}
	if fallbackCalls != 0 {
		t.Fatal("denied provider received credentials")
	}
	if _, err := core.AuthenticatePassword(context.Background(), "fallback", authconnector.PasswordRequest{Identifier: "different@other.test", Secret: "verified"}); err != nil {
		t.Fatal(err)
	}
	if fallbackCalls != 1 {
		t.Fatalf("explicit fallback not honored for other domain: %d", fallbackCalls)
	}
}

func TestRouting0293RequiresExplicitAndRejectsBadConfigurations(t *testing.T) {
	core := New(repository.NewMemoryRepository("http://test.invalid"))
	calls := 0
	if err := core.Register(routingConnector0293{id: "company", calls: &calls}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(RoutingConfig{Version: 1, RequireExplicitProvider: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := core.RoutePasswordProvider("", "username"); !errors.Is(err, ErrRoutingRequired) {
		t.Fatalf("unrouted username: %v", err)
	}
	if selected, err := core.RoutePasswordProvider("company", "username"); err != nil || selected != "company" {
		t.Fatalf("explicit provider: %q %v", selected, err)
	}
	for _, bad := range []RoutingConfig{
		{Version: 2}, {Version: 1, DefaultProvider: "missing"}, {Version: 1, Rules: []RoutingRule{{EmailDomain: "*.example.test", ProviderID: "company"}}},
		{Version: 1, Rules: []RoutingRule{{EmailDomain: "corp.test", ProviderID: "missing"}}},
		{Version: 1, Rules: []RoutingRule{{EmailDomain: "corp.test", ProviderID: "company"}, {EmailDomain: "CORP.TEST", ProviderID: "company"}}},
		{Version: 1, LinkingAllowProviders: []string{"missing"}},
		{Version: 1, DisableLinking: true, LinkingAllowProviders: []string{"company"}},
	} {
		if err := core.ConfigureRouting(bad); err == nil {
			t.Fatalf("accepted invalid policy: %+v", bad)
		}
	}
	if _, err := core.RoutePasswordProvider("", "username"); !errors.Is(err, ErrRoutingRequired) {
		t.Fatalf("invalid policy partially applied: %v", err)
	}
	copy := core.Routing()
	copy.DefaultProvider = "attacker"
	if got := core.Routing().DefaultProvider; got != "" {
		t.Fatalf("routing exposed mutable state: %q", got)
	}
}

func TestRouting0293ValidatedLinkingAndIssuerCollision(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	second, err := repo.SaveUser(model.User{Email: "second@enterprise.test", DisplayName: "Second", RoleID: "player", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	core := New(repo)
	calls := 0
	if err := core.Register(routingConnector0293{id: "company", issuer: "https://one.test", calls: &calls}); err != nil {
		t.Fatal(err)
	}
	if err := core.Register(routingConnector0293{id: "forbidden", issuer: "https://two.test", calls: &calls}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(RoutingConfig{Version: 1, DefaultProvider: "company", LinkingAllowProviders: []string{"company"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "forbidden", authconnector.PasswordRequest{Identifier: "who", Secret: "verified"}); !errors.Is(err, ErrLinkingDisabled) {
		t.Fatalf("forbidden provider link: %v", err)
	}
	if calls != 0 {
		t.Fatal("forbidden provider received password")
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "company", authconnector.PasswordRequest{Identifier: "who", Secret: "wrong"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("link accepted invalid password: %v", err)
	}
	if identities := repo.ListAuthIdentities("admin"); len(identities) != 1 {
		t.Fatalf("invalid proof modified identities: %+v", identities)
	}
	linked, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "company", authconnector.PasswordRequest{Identifier: "who", Secret: "verified"})
	if err != nil || linked.UserID != "admin" || linked.Issuer != "https://one.test" {
		t.Fatalf("link: %+v %v", linked, err)
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), second.ID, "company", authconnector.PasswordRequest{Identifier: "who", Secret: "verified"}); authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("identity reassigned to second canonical user: %v", err)
	}
	found, err := repo.GetAuthIdentityByIssuer("company", "https://one.test", "42")
	if err != nil || found.UserID != "admin" {
		t.Fatalf("identity changed on failed link: %+v %v", found, err)
	}
}

func TestRouting0293ConfigFileNoUnrecognizedFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routing.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"requireExplicitProvider":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRoutingConfig("", file)
	if err != nil || !cfg.RequireExplicitProvider {
		t.Fatalf("loaded config: %+v %v", cfg, err)
	}
	if _, err := LoadRoutingConfig(`{"version":1}`, file); err == nil {
		t.Fatal("accepted ambiguous env/file")
	}
	for _, raw := range []string{`{"version":1,"unk":true}`, `{"version":1} {"version":1}`, `{"version":1,"version":2}`, `{"version":1,"rules":[{"emailDomain":"corp.test","emailDomain":"other.test","providerId":"company"}]}`, strings.Repeat("x", 65537)} {
		if _, err := LoadRoutingConfig(raw, ""); err == nil {
			t.Fatalf("accepted invalid file size or JSON")
		}
	}
	defaults, err := LoadRoutingConfig("", "")
	if err != nil || defaults.Version != 1 || defaults.DefaultProvider != "local" {
		t.Fatalf("legacy defaults changed: %+v %v", defaults, err)
	}
}

func TestRouting0293DisableLinkingDoesNotDisableAuthentication(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core := New(repo)
	count := 0
	if err := core.RegisterWithPolicy(routingConnector0293{id: "company", issuer: "https://one.test", calls: &count}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(RoutingConfig{Version: 1, DefaultProvider: "company", DisableLinking: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "company", authconnector.PasswordRequest{Identifier: "alice", Secret: "verified"}); !errors.Is(err, ErrLinkingDisabled) {
		t.Fatalf("disabled linking accepted: %v", err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "", authconnector.PasswordRequest{Identifier: "alice", Secret: "verified"}); err != nil {
		t.Fatalf("normal login blocked by link policy: %v", err)
	}
	if count != 1 {
		t.Fatalf("linking accidentally contacted provider: calls=%d", count)
	}
}

func TestRouting0293DisableNewLinksPreservesExistingCredentialRefresh(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core := New(repo)
	calls := 0
	if err := core.Register(routingConnector0293{id: "company", issuer: "https://one.test", calls: &calls}); err != nil {
		t.Fatal(err)
	}
	original := authconnector.Authentication{Identity: authconnector.Identity{Issuer: "https://one.test", Subject: "subject-one", Email: "old@company.test"}, AuthMethods: []string{"password"}}
	linked, err := core.LinkAuthenticatedIdentity("admin", "company", original)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ConfigureRouting(RoutingConfig{Version: 1, DefaultProvider: "company", DisableLinking: true}); err != nil {
		t.Fatal(err)
	}
	fresh := authconnector.Authentication{Identity: authconnector.Identity{Issuer: "https://one.test", Subject: "subject-one", Email: "new@company.test"}, AuthMethods: []string{"refresh"}}
	updated, err := core.RefreshLinkedIdentity("admin", "company", linked.ID, fresh)
	if err != nil || updated.ID != linked.ID || updated.Email != "new@company.test" {
		t.Fatalf("refresh of existing link blocked: %+v %v", updated, err)
	}
	if _, err := core.LinkAuthenticatedIdentity("admin", "company", fresh); !errors.Is(err, ErrLinkingDisabled) {
		t.Fatalf("link policy bypass: %v", err)
	}
	for _, bad := range []authconnector.Authentication{
		{Identity: authconnector.Identity{Issuer: "https://two.test", Subject: "subject-one"}, AuthMethods: []string{"refresh"}},
		{Identity: authconnector.Identity{Issuer: "https://one.test", Subject: "different"}, AuthMethods: []string{"refresh"}},
	} {
		if _, err := core.RefreshLinkedIdentity("admin", "company", linked.ID, bad); authconnector.CodeOf(err) != authconnector.ErrConflict {
			t.Fatalf("repointed refresh accepted: %v", err)
		}
	}
	if _, err := core.RefreshLinkedIdentity("admin", "company", "wrong-id", fresh); authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("wrong linked credential accepted: %v", err)
	}
	saved, err := repo.GetAuthIdentityByIssuer("company", "https://one.test", "subject-one")
	if err != nil || saved.ID != linked.ID || saved.Email != "new@company.test" {
		t.Fatalf("linked identity compromised: %+v %v", saved, err)
	}
}
