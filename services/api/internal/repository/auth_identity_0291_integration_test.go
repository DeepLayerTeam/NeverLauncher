//go:build !neverlauncher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// Requires a disposable real PostgreSQL database with migration privileges.
// Exercises issuer isolation, credential persistence, and UUID protections on
// the production SQL path rather than against a mock SQL driver.
func TestCanonicalIssuerPostgres0291(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable NEVERLAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected PostgreSQL repository")
	}
	defer a.db.Close()
	b, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected PostgreSQL repository")
	}
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	users := []string{"issuer-one-" + stamp, "issuer-two-" + stamp}
	for _, id := range users {
		_, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,$3)`, id, id+"@identity.invalid", id)
		if err != nil {
			t.Fatal(err)
		}
		defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, id)
	}
	one, err := a.SaveAuthIdentity(model.AuthIdentity{UserID: users[0], Provider: "oidc-0291", Issuer: "https://first.example.test", Subject: "same", Email: "shared@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := b.SaveAuthIdentity(model.AuthIdentity{UserID: users[1], Provider: "oidc-0291", Issuer: "https://second.example.test", Subject: "same", Email: "shared@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if one.ID == two.ID || one.UserID == two.UserID {
		t.Fatal("cross-issuer account merge")
	}
	if _, err := b.GetAuthIdentity("oidc-0291", "same"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unqualified lookup: %v", err)
	}
	got, err := b.GetAuthIdentityByIssuer("oidc-0291", one.Issuer, "same")
	if err != nil || got.UserID != one.UserID {
		t.Fatalf("cross-replica issuer lookup: %+v / %v", got, err)
	}
	for _, identity := range []model.AuthIdentity{one, two} {
		_, err = a.SaveProviderCredential(model.ProviderCredential{UserID: identity.UserID, IdentityID: identity.ID, Provider: identity.Provider, Subject: identity.Subject, EncryptedRefreshToken: "encrypted-fixture"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.GetProviderCredentialByIdentity(users[1], two.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SaveAuthIdentity(model.AuthIdentity{UserID: users[1], Provider: "oidc-0291", Issuer: one.Issuer, Subject: "same"}); err == nil {
		t.Fatal("subject reassignment accepted")
	}
	profile, err := a.SaveMinecraftProfile(model.MinecraftProfile{UserID: users[0], UUID: "0d011234-aaaa-4bbb-8ccc-123400002911", Name: "IssuerTest0291", Issuer: "neverlauncher", Realm: "local", Subject: "0d011234-aaaa-4bbb-8ccc-123400002911"})
	if err != nil {
		t.Fatal(err)
	}
	profile.UUID = "0d011234-aaaa-4bbb-8ccc-123400002912"
	if _, err := b.SaveMinecraftProfile(profile); !errors.Is(err, ErrConflict) {
		t.Fatalf("unexpected UUID mutation: %v", err)
	}
	if _, err := b.db.ExecContext(ctx, `UPDATE minecraft_profiles SET uuid=$1 WHERE user_id=$2`, profile.UUID, users[0]); err == nil {
		t.Fatal("direct SQL UUID mutation bypassed trigger")
	}
}
