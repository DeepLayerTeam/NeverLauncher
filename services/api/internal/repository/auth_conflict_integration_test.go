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

// Проверяет промышленные ограничения идентичностей PostgreSQL через отдельные
// соединения: одинаковые issuer+subject нельзя назначить другому каноническому
// пользователю, как нельзя и незаметно менять subject того же пользователя.
func TestAuthIdentityCollisionPostgres0293(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("требуется одноразовая база в LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("Ожидался репозиторий PostgreSQL")
	}
	defer a.db.Close()
	b, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("Ожидался репозиторий PostgreSQL")
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
		t.Fatalf("Переназначение идентификатора между пользователями: %v", err)
	}
	if _, err := b.SaveAuthIdentity(model.AuthIdentity{UserID: first, Provider: linked.Provider, Issuer: linked.Issuer, Subject: "another", Email: linked.Email}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Замена субъекта того же пользователя: %v", err)
	}
	stable, err := b.GetAuthIdentityByIssuer(linked.Provider, linked.Issuer, linked.Subject)
	if err != nil || stable.UserID != first || stable.ID != linked.ID {
		t.Fatalf("Каноническая идентичность неожиданно изменилась: %+v %v", stable, err)
	}
}
