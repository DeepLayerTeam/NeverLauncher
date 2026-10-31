//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Exercises the production PostgreSQL identity constraints using separate
// connections; a duplicate issuer+subject may never be assigned to another
// canonical user, nor may the same user silently change subject.
func TestAuthIdentityCollisionPostgres0293(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
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
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	first, second := "route-a-"+suffix, "route-b-"+suffix
	for _, id := range []string{first, second} {
		if _, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,$3)`, id, id+"@identity.invalid", id); err != nil {
			t.Fatal(err)
		}
		defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, id)
	}
	linked, err := a.SaveAuthIdentity(model.AuthIdentity{UserID: first, Provider: "sql-route-0293", Issuer: "https://issuer.test", Subject: "subject", Email: "shared@company.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.SaveAuthIdentity(model.AuthIdentity{UserID: second, Provider: linked.Provider, Issuer: linked.Issuer, Subject: linked.Subject, Email: linked.Email}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-user identity reassignment: %v", err)
	}
	if _, err := b.SaveAuthIdentity(model.AuthIdentity{UserID: first, Provider: linked.Provider, Issuer: linked.Issuer, Subject: "another", Email: linked.Email}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-user subject replacement: %v", err)
	}
	stable, err := b.GetAuthIdentityByIssuer(linked.Provider, linked.Issuer, linked.Subject)
	if err != nil || stable.UserID != first || stable.ID != linked.ID {
		t.Fatalf("canonical identity changed: %+v %v", stable, err)
	}
}
