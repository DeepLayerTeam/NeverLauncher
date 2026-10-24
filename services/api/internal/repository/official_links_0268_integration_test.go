package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Requires a disposable migrated PostgreSQL database. Never run against prod.
func TestOfficialNeverLinkAtomicOwnership0268(t *testing.T) {
	dsn := os.Getenv("NEVER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set NEVER_TEST_POSTGRES_DSN for isolated PostgreSQL integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if _, err := (&SQLRepository{db: db}).ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	stamp := time.Now().UnixNano()
	a, b := fmt.Sprintf("official-link-a-%d", stamp), fmt.Sprintf("official-link-b-%d", stamp)
	for _, owner := range []string{a, b} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,$3)`, owner, owner+"@example.test", owner); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, owner)
	}
	repo := &SQLRepository{db: db}
	const uuid = "123456789abcdef0123456789abcdef0"
	first, err := repo.UpsertOfficialLink0268(ctx, a, uuid, "FirstName")
	if err != nil {
		t.Fatal(err)
	}
	if first.MinecraftUUID != uuid || first.MinecraftName != "FirstName" {
		t.Fatalf("unexpected first binding %#v", first)
	}
	if _, err := repo.UpsertOfficialLink0268(ctx, b, uuid, "Stolen"); !errors.Is(err, ErrOfficialLinkOwned0268) {
		t.Fatalf("expected ownership conflict, got %v", err)
	}
	mine, err := repo.ListOfficialLinks0268(ctx, a)
	if err != nil || len(mine) != 1 {
		t.Fatalf("owner list: %#v %v", mine, err)
	}
	other, err := repo.ListOfficialLinks0268(ctx, b)
	if err != nil || len(other) != 0 {
		t.Fatalf("other owner list: %#v %v", other, err)
	}
	if err := repo.RemoveOfficialLink0268(ctx, b, uuid); !errors.Is(err, ErrOfficialLinkAbsent0268) {
		t.Fatalf("wrong owner deletion: %v", err)
	}
	renamed, err := repo.UpsertOfficialLink0268(ctx, a, uuid, "NewName")
	if err != nil || renamed.MinecraftName != "NewName" {
		t.Fatalf("same owner rename: %#v %v", renamed, err)
	}
	if err := repo.RemoveOfficialLink0268(ctx, a, uuid); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertOfficialLink0268(ctx, b, uuid, "NewOwner"); err != nil {
		t.Fatal(err)
	}
}
