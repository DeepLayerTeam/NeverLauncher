package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
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
		t.Fatalf("Манифест не приведён к каноническому виду: %#v", first)
	}
	if len(first.Manifest.Permissions) != 2 {
		t.Fatalf("Разрешения не нормализованы: %#v", first.Manifest.Permissions)
	}

	second, err := repo.SaveExtensionVersion(ctx, manifest)
	if err != nil {
		t.Fatalf("Ошибка идемпотентного сохранения: %v", err)
	}
	if first.ManifestSHA256 != second.ManifestSHA256 || !first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("Идемпотентное сохранение изменило неизменяемую версию: %#v %#v", first, second)
	}

	mutated := manifest
	mutated.Name = "Changed bytes"
	if _, err := repo.SaveExtensionVersion(ctx, mutated); !errors.Is(err, ErrImmutable) {
		t.Fatalf("Ожидалась ошибка ErrImmutable, получено: %v", err)
	}
	identity, err := repo.GetExtension(ctx, manifest.ID)
	if err != nil || identity.Name != manifest.Name {
		t.Fatalf("Неудачная запись неизменяемой версии изменила идентичность расширения: %#v %v", identity, err)
	}
	permissions, err := repo.ListExtensionPermissions(ctx, manifest.ID, manifest.Version)
	if err != nil || len(permissions) != 2 || permissions[0] != "release:read" || permissions[1] != "storage:read" {
		t.Fatalf("Несовпадение нормализованных разрешений: %#v %v", permissions, err)
	}
	dependencies, err := repo.ListExtensionDependencies(ctx, manifest.ID, manifest.Version)
	if err != nil || len(dependencies) != 1 || dependencies[0].ID != "ru.example.base" {
		t.Fatalf("Несовпадение нормализованных зависимостей: %#v %v", dependencies, err)
	}

	hijack := manifest
	hijack.Version = "1.2.4"
	hijack.Publisher = "Other Publisher"
	if _, err := repo.SaveExtensionVersion(ctx, hijack); !errors.Is(err, ErrConflict) {
		t.Fatalf("Ожидалась ошибка издателя ErrConflict, получено: %v", err)
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
		t.Fatalf("Не назначены временные метки: %#v", installed)
	}
	got, err := repo.GetExtensionInstall(ctx, manifest.ID, "project", "demo-project")
	if err != nil || got.Version != manifest.Version {
		t.Fatalf("Получение установки: %#v %v", got, err)
	}
	if err := repo.DeleteExtensionInstall(ctx, manifest.ID, "project", "demo-project"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExtensionInstall(ctx, manifest.ID, "project", "demo-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Удалённая установка должна отсутствовать, получено: %v", err)
	}
}

func TestExtensionsCore0201Postgres(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		dsn = os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("Строка подключения DSN для тестовой PostgreSQL не задана")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("Репозиторий не является SQLRepository")
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
		t.Fatal("Контрольная сумма манифеста пуста")
	}
	permissions, err := repo.ListExtensionPermissions(ctx, manifest.ID, manifest.Version)
	if err != nil || len(permissions) != 2 {
		t.Fatalf("Разрешения: %#v %v", permissions, err)
	}
	dependencies, err := repo.ListExtensionDependencies(ctx, manifest.ID, manifest.Version)
	if err != nil || len(dependencies) != 1 || dependencies[0].ID != "ru.example.base" {
		t.Fatalf("Зависимости: %#v %v", dependencies, err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE extension_versions SET api='tampered' WHERE extension_id=$1 AND version=$2`, manifest.ID, manifest.Version); err == nil {
		t.Fatal("База данных допустила изменение неизменяемой версии расширения")
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE extensions SET publisher='attacker' WHERE id=$1`, manifest.ID); err == nil {
		t.Fatal("База данных допустила изменение издателя")
	}
	install, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Version: manifest.Version, Scope: "global", Source: "local"})
	if err != nil || install.ExtensionID != manifest.ID {
		t.Fatalf("Установка: %#v %v", install, err)
	}
}
