package federation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
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
		t.Fatalf("Маршрутизация по домену: %q %v", selected, err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "", authconnector.PasswordRequest{Identifier: "user@enterprise.test", Secret: "verified"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("Неожиданная ошибка основного провайдера: %v", err)
	}
	if primaryCalls != 1 || fallbackCalls != 0 {
		t.Fatalf("Произошёл переход на резервного провайдера: основной=%d резервный=%d", primaryCalls, fallbackCalls)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "fallback", authconnector.PasswordRequest{Identifier: "user@enterprise.test", Secret: "verified"}); !errors.Is(err, ErrRoutingDenied) {
		t.Fatalf("Обход строгой маршрутизации: %v", err)
	}
	if fallbackCalls != 0 {
		t.Fatal("Отклонённый провайдер получил учётные данные")
	}
	if _, err := core.AuthenticatePassword(context.Background(), "fallback", authconnector.PasswordRequest{Identifier: "different@other.test", Secret: "verified"}); err != nil {
		t.Fatal(err)
	}
	if fallbackCalls != 1 {
		t.Fatalf("Явно заданный резервный маршрут для другого домена проигнорирован: %d", fallbackCalls)
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
		t.Fatalf("Имя пользователя не сопоставлено с маршрутом: %v", err)
	}
	if selected, err := core.RoutePasswordProvider("company", "username"); err != nil || selected != "company" {
		t.Fatalf("Явно указанный провайдер: %q %v", selected, err)
	}
	for _, bad := range []RoutingConfig{
		{Version: 2}, {Version: 1, DefaultProvider: "missing"}, {Version: 1, Rules: []RoutingRule{{EmailDomain: "*.example.test", ProviderID: "company"}}},
		{Version: 1, Rules: []RoutingRule{{EmailDomain: "corp.test", ProviderID: "missing"}}},
		{Version: 1, Rules: []RoutingRule{{EmailDomain: "corp.test", ProviderID: "company"}, {EmailDomain: "CORP.TEST", ProviderID: "company"}}},
		{Version: 1, LinkingAllowProviders: []string{"missing"}},
		{Version: 1, DisableLinking: true, LinkingAllowProviders: []string{"company"}},
	} {
		if err := core.ConfigureRouting(bad); err == nil {
			t.Fatalf("Принята некорректная политика: %+v", bad)
		}
	}
	if _, err := core.RoutePasswordProvider("", "username"); !errors.Is(err, ErrRoutingRequired) {
		t.Fatalf("Некорректная политика частично применена: %v", err)
	}
	copy := core.Routing()
	copy.DefaultProvider = "attacker"
	if got := core.Routing().DefaultProvider; got != "" {
		t.Fatalf("Маршрутизация раскрыла изменяемое состояние: %q", got)
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
		t.Fatalf("Запрещённая привязка провайдера: %v", err)
	}
	if calls != 0 {
		t.Fatal("Запрещённый провайдер получил пароль")
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "company", authconnector.PasswordRequest{Identifier: "who", Secret: "wrong"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("При привязке принят неверный пароль: %v", err)
	}
	if identities := repo.ListAuthIdentities("admin"); len(identities) != 1 {
		t.Fatalf("Некорректное доказательство изменило идентичности: %+v", identities)
	}
	linked, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "company", authconnector.PasswordRequest{Identifier: "who", Secret: "verified"})
	if err != nil || linked.UserID != "admin" || linked.Issuer != "https://one.test" {
		t.Fatalf("Привязка: %+v %v", linked, err)
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), second.ID, "company", authconnector.PasswordRequest{Identifier: "who", Secret: "verified"}); authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("Идентичность переназначена второму каноническому пользователю: %v", err)
	}
	found, err := repo.GetAuthIdentityByIssuer("company", "https://one.test", "42")
	if err != nil || found.UserID != "admin" {
		t.Fatalf("Идентичность изменилась после неудачной привязки: %+v %v", found, err)
	}
}

func TestRouting0293ConfigFileNoUnrecognizedFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routing.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"requireExplicitProvider":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRoutingConfig("", file)
	if err != nil || !cfg.RequireExplicitProvider {
		t.Fatalf("Загруженная конфигурация: %+v %v", cfg, err)
	}
	if _, err := LoadRoutingConfig(`{"version":1}`, file); err == nil {
		t.Fatal("Принята неоднозначная конфигурация окружения или файла")
	}
	for _, raw := range []string{`{"version":1,"unk":true}`, `{"version":1} {"version":1}`, `{"version":1,"version":2}`, `{"version":1,"rules":[{"emailDomain":"corp.test","emailDomain":"other.test","providerId":"company"}]}`, strings.Repeat("x", 65537)} {
		if _, err := LoadRoutingConfig(raw, ""); err == nil {
			t.Fatalf("Принят некорректный размер файла или JSON")
		}
	}
	defaults, err := LoadRoutingConfig("", "")
	if err != nil || defaults.Version != 1 || defaults.DefaultProvider != "local" {
		t.Fatalf("Изменились исходные настройки совместимости: %+v %v", defaults, err)
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
		t.Fatalf("Разрешена отключённая привязка: %v", err)
	}
	if _, err := core.AuthenticatePassword(context.Background(), "", authconnector.PasswordRequest{Identifier: "alice", Secret: "verified"}); err != nil {
		t.Fatalf("Политика привязки заблокировала обычный вход: %v", err)
	}
	if count != 1 {
		t.Fatalf("При привязке ошибочно выполнено обращение к провайдеру: вызовов=%d", count)
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
		t.Fatalf("Заблокировано обновление существующей привязки: %+v %v", updated, err)
	}
	if _, err := core.LinkAuthenticatedIdentity("admin", "company", fresh); !errors.Is(err, ErrLinkingDisabled) {
		t.Fatalf("Обход политики привязки: %v", err)
	}
	for _, bad := range []authconnector.Authentication{
		{Identity: authconnector.Identity{Issuer: "https://two.test", Subject: "subject-one"}, AuthMethods: []string{"refresh"}},
		{Identity: authconnector.Identity{Issuer: "https://one.test", Subject: "different"}, AuthMethods: []string{"refresh"}},
	} {
		if _, err := core.RefreshLinkedIdentity("admin", "company", linked.ID, bad); authconnector.CodeOf(err) != authconnector.ErrConflict {
			t.Fatalf("Принято обновление с переназначением привязки: %v", err)
		}
	}
	if _, err := core.RefreshLinkedIdentity("admin", "company", "wrong-id", fresh); authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("Приняты неправильные учётные данные привязки: %v", err)
	}
	saved, err := repo.GetAuthIdentityByIssuer("company", "https://one.test", "subject-one")
	if err != nil || saved.ID != linked.ID || saved.Email != "new@company.test" {
		t.Fatalf("Скомпрометирована привязанная идентичность: %+v %v", saved, err)
	}
}
