package federation

import (
	"context"
	"errors"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type issuerFixture0291 struct{}

func (issuerFixture0291) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "multi", DisplayName: "Multi", Version: "1", Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth}}
}
func (issuerFixture0291) Health(context.Context) error { return nil }
func (issuerFixture0291) AuthenticatePassword(_ context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	return authconnector.Authentication{Identity: authconnector.Identity{Issuer: req.Identifier, Subject: "same", Email: "shared@example.test", DisplayName: "Test"}}, nil
}

func TestFederationCannotMergeIssuerBySubjectOrEmail0291(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core := New(repo)
	if err := core.RegisterWithPolicy(issuerFixture0291{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	first, err := core.AuthenticatePassword(context.Background(), "multi", authconnector.PasswordRequest{Identifier: "https://issuer-one.test"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := core.AuthenticatePassword(context.Background(), "multi", authconnector.PasswordRequest{Identifier: "https://issuer-two.test"})
	if err != nil {
		t.Fatal(err)
	}
	if first.User.ID == second.User.ID || first.User.Email == second.User.Email || first.Identity.ID == second.Identity.ID {
		t.Fatal("Адрес электронной почты и субъект объединены между разными издателями токенов")
	}
	if first.Identity.Email != "shared@example.test" || second.Identity.Email != "shared@example.test" {
		t.Fatal("Потеряно исходное утверждение об адресе электронной почты")
	}
	again, err := core.AuthenticatePassword(context.Background(), "multi", authconnector.PasswordRequest{Identifier: "https://issuer-one.test"})
	if err != nil || again.User.ID != first.User.ID {
		t.Fatal("Идентификатор издателя токена нестабилен", err)
	}
	if _, err := repo.GetAuthIdentity("multi", "same"); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Ошибочно принят неоднозначный поиск без указания области: %v", err)
	}
}

func TestLegacyIssuerRequiresExplicitLink0291(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	_, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "multi", Subject: "same"})
	if err != nil {
		t.Fatal(err)
	}
	core := New(repo)
	if err := core.RegisterWithPolicy(issuerFixture0291{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}); err != nil {
		t.Fatal(err)
	}
	proof := authconnector.Authentication{Identity: authconnector.Identity{Issuer: "https://issuer-one.test", Subject: "same"}}
	if _, err := core.AuthenticatePassword(context.Background(), "multi", authconnector.PasswordRequest{Identifier: proof.Identity.Issuer}); !errors.Is(err, ErrIdentityNotLinked) {
		t.Fatalf("Старая учётная запись перехвачена или затенена: %v", err)
	}
	if _, err := core.LinkAuthenticatedIdentity("admin", "multi", proof); err != nil {
		t.Fatal("явная ссылка миграции", err)
	}
	result, err := core.AuthenticatePassword(context.Background(), "multi", authconnector.PasswordRequest{Identifier: proof.Identity.Issuer})
	if err != nil || result.User.ID != "admin" {
		t.Fatalf("Ошибка привязанной идентичности: %+v / %v", result, err)
	}
}

func TestPasswordProofLinksExistingLauncherIdentity0291(t *testing.T) {
	repo := repository.NewMemoryRepository("http://test.invalid")
	core := New(repo)
	if err := core.Register(issuerFixture0291{}); err != nil {
		t.Fatal(err)
	}
	req := authconnector.PasswordRequest{Identifier: "https://issuer.test", Secret: "valid-provider-password"}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "multi", req); err != nil {
		t.Fatal(err)
	}
	result, err := core.AuthenticatePassword(context.Background(), "multi", req)
	if err != nil || result.User.ID != "admin" {
		t.Fatalf("Подтверждение пароля не активировало процесс издателя токена: %+v / %v", result, err)
	}
	if _, _, err := core.LinkPasswordIdentity(context.Background(), "admin", "multi", authconnector.PasswordRequest{Identifier: "https://issuer.test"}); err == nil {
		t.Fatal("Ошибочно принято отсутствие внешнего пароля")
	}
}
