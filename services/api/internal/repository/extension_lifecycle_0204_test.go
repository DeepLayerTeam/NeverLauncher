package repository

import (
	"context"
	"errors"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestExtensionLifecycleMemoryStateMachine0204(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("http://example.test")
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.lifecycle", Name: "Lifecycle", Version: "1.0.0", Publisher: "deeplayer.team", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	identity := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	installed, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: manifest.ID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
		PackageIdentity: identity, CurrentPackageIdentity: identity, Operation: "install", Source: "test", ExpectedGeneration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Generation != 1 || installed.CurrentState != model.ExtensionInstallStateDisabled || installed.Enabled {
		t.Fatalf("install=%+v", installed)
	}

	enabled, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: manifest.ID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
		PackageIdentity: identity, CurrentPackageIdentity: identity, Operation: "enable", Source: "test", ExpectedGeneration: 1, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.Generation != 2 || !enabled.Enabled {
		t.Fatalf("enable=%+v", enabled)
	}

	_, err = repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: manifest.ID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
		PackageIdentity: identity, CurrentPackageIdentity: identity, Operation: "disable", Source: "stale", ExpectedGeneration: 1,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation must conflict, got %v", err)
	}

	revisions, err := repo.ListExtensionInstallRevisions(ctx, manifest.ID, "global", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 2 || revisions[0].Operation != "enable" || revisions[1].Operation != "install" {
		t.Fatalf("revisions=%+v", revisions)
	}
}

func TestExtensionLifecycleProjectScopeIsolation0204(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("http://example.test")
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.scope", Name: "Scope", Version: "1.0.0", Publisher: "deeplayer.team", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	id := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, project := range []string{"project-a", "project-b"} {
		if _, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: manifest.ID, Scope: "project", ScopeID: project, DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, PackageIdentity: id, CurrentPackageIdentity: id, Operation: "install", ExpectedGeneration: 0}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := repo.GetExtensionInstallState(ctx, manifest.ID, "project", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.GetExtensionInstallState(ctx, manifest.ID, "project", "project-b")
	if err != nil {
		t.Fatal(err)
	}
	if a.ScopeID == b.ScopeID || a.Generation != 1 || b.Generation != 1 {
		t.Fatalf("scope isolation failed: a=%+v b=%+v", a, b)
	}
}
