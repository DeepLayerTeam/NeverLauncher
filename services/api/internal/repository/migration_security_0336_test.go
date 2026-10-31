package repository

import (
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/gravitcredentials"
	"gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"testing"
)

func TestMigrationSecurityTargetDerivation0336(t *testing.T) {
	rows := []gravitcredentials.Row{
		{Provider: "fileauth", SourceID: "local", Username: "Alpha336", UUID: "11111111-2222-4333-8444-555555555555", State: "imported"},
		{Provider: "sql", SourceID: "id-33", Username: "Beta336", UUID: "22222222-2222-4333-8444-555555555555", State: "imported"},
		{Provider: "sql", SourceID: "not-ours", Username: "Gamma336", UUID: "33333333-2222-4333-8444-555555555555", State: "existing_unchanged"},
	}
	targets, err := migrationSecurityTargets0336(rows)
	if err != nil || len(targets) != 2 || targets[0].UserID != "gravit-fileauth-11111111222243338444555555555555" || targets[1].UserID != migratedUserID0335FromRow(rows[1]) {
		t.Fatalf("bad targets: %#v %v", targets, err)
	}
	if targets[1].UserID != migratedUserID0335FromRow(rows[1]) {
		t.Fatal("SQL user ID mismatch")
	}
	rows = append(rows, rows[0])
	if _, err = migrationSecurityTargets0336(rows); !errors.Is(err, migrationworkflow.ErrConflict) {
		t.Fatalf("duplicate source identity accepted: %v", err)
	}
	rows = []gravitcredentials.Row{{Provider: "unknown", SourceID: "x", Username: "Foo", UUID: "one", State: "imported"}}
	if _, err = migrationSecurityTargets0336(rows); !errors.Is(err, migrationworkflow.ErrConflict) {
		t.Fatal("unknown provider accepted")
	}
}
