package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func extensionManifest0201ForTest() model.ExtensionManifest {
	return model.ExtensionManifest{
		SchemaVersion: "2.0",
		ID:            "ru.example.extension",
		Name:          "Example Extension",
		Version:       "1.2.3",
		Publisher:     "Example Publisher",
		API:           "3.7",
		Targets: []model.ExtensionTarget{
			{Kind: "cli", Entrypoint: "bin/extension"},
			{Kind: "backend", Entrypoint: "bin/backend"},
		},
		Permissions:  []string{"release:read", "storage:read", "release:read"},
		Dependencies: []model.ExtensionDependency{{ID: "ru.example.base", Version: ">=1.0.0"}},
	}
}

func TestExtensionMemoryRepositoryPersistsImmutableCanonicalVersions0201(t *testing.T) {
	repo := NewMemoryRepository("http://example.test")
	ctx := context.Background()
	manifest := extensionManifest0201ForTest()

	first, err := repo.SaveExtensionVersion(ctx, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestSHA256 == "" || first.Manifest.Targets[0].Kind != "backend" {
		t.Fatalf("manifest was not canonicalized: %#v", first)
	}
	if len(first.Manifest.Permissions) != 2 {
		t.Fatalf("permissions were not normalized: %#v", first.Manifest.Permissions)
	}

	second, err := repo.SaveExtensionVersion(ctx, manifest)
	if err != nil {
		t.Fatalf("idempotent save failed: %v", err)
	}
	if first.ManifestSHA256 != second.ManifestSHA256 || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("idempotent save changed immutable version: %#v %#v", first, second)
	}

	mutated := manifest
	mutated.Name = "Changed bytes"
	if _, err := repo.SaveExtensionVersion(ctx, mutated); !errors.Is(err, ErrImmutable) {
		t.Fatalf("expected ErrImmutable, got %v", err)
	}
	identity, err := repo.GetExtension(ctx, manifest.ID)
	if err != nil || identity.Name != manifest.Name {
		t.Fatalf("failed immutable write changed extension identity: %#v %v", identity, err)
	}
	permissions, err := repo.ListExtensionPermissions(ctx, manifest.ID, manifest.Version)
	if err != nil || len(permissions) != 2 || permissions[0] != "release:read" || permissions[1] != "storage:read" {
		t.Fatalf("normalized permissions mismatch: %#v %v", permissions, err)
	}
	dependencies, err := repo.ListExtensionDependencies(ctx, manifest.ID, manifest.Version)
	if err != nil || len(dependencies) != 1 || dependencies[0].ID != "ru.example.base" {
		t.Fatalf("normalized dependencies mismatch: %#v %v", dependencies, err)
	}

	hijack := manifest
	hijack.Version = "1.2.4"
	hijack.Publisher = "Other Publisher"
	if _, err := repo.SaveExtensionVersion(ctx, hijack); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected publisher ErrConflict, got %v", err)
	}
}

func TestExtensionMemoryRepositoryInstallStateReferencesExistingVersion0201(t *testing.T) {
	repo := NewMemoryRepository("http://example.test")
	ctx := context.Background()
	manifest := extensionManifest0201ForTest()
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}

	installed, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Version: manifest.Version, Scope: "project", ScopeID: "demo-project", Enabled: false, Source: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if installed.InstalledAt.IsZero() || installed.UpdatedAt.IsZero() {
		t.Fatalf("timestamps not assigned: %#v", installed)
	}
	got, err := repo.GetExtensionInstall(ctx, manifest.ID, "project", "demo-project")
	if err != nil || got.Version != manifest.Version {
		t.Fatalf("get install: %#v %v", got, err)
	}
	if err := repo.DeleteExtensionInstall(ctx, manifest.ID, "project", "demo-project"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExtensionInstall(ctx, manifest.ID, "project", "demo-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted install should be missing, got %v", err)
	}
}

func TestNeverExtensionsCore0201Postgres(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		dsn = os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("PostgreSQL test DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("repository is not SQLRepository")
	}
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	manifest := extensionManifest0201ForTest()
	manifest.ID = "ru.example.extension0201pg"
	_, _ = repo.db.ExecContext(ctx, `DELETE FROM extension_installs WHERE extension_id=$1`, manifest.ID)
	_, _ = repo.db.ExecContext(ctx, `DELETE FROM extensions WHERE id=$1`, manifest.ID)

	stored, err := repo.SaveExtensionVersion(ctx, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ManifestSHA256 == "" {
		t.Fatal("manifest digest is empty")
	}
	permissions, err := repo.ListExtensionPermissions(ctx, manifest.ID, manifest.Version)
	if err != nil || len(permissions) != 2 {
		t.Fatalf("permissions: %#v %v", permissions, err)
	}
	dependencies, err := repo.ListExtensionDependencies(ctx, manifest.ID, manifest.Version)
	if err != nil || len(dependencies) != 1 || dependencies[0].ID != "ru.example.base" {
		t.Fatalf("dependencies: %#v %v", dependencies, err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE extension_versions SET api='tampered' WHERE extension_id=$1 AND version=$2`, manifest.ID, manifest.Version); err == nil {
		t.Fatal("database accepted immutable extension version mutation")
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE extensions SET publisher='attacker' WHERE id=$1`, manifest.ID); err == nil {
		t.Fatal("database accepted publisher mutation")
	}
	install, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Version: manifest.Version, Scope: "global", Source: "local"})
	if err != nil || install.ExtensionID != manifest.ID {
		t.Fatalf("install: %#v %v", install, err)
	}
}
