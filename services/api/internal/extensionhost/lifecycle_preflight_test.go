package extensionhost

import (
	"context"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"strings"
	"testing"
)

func TestHostCannotStartStaleInstallationAfterDisable0424(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "example.stale"
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Stale", Version: "1.0.0", Publisher: "test.publisher", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	initial, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled, Operation: "disable", ExpectedGeneration: initial.Generation})
	if err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.StartInstallation(ctx, initial); err == nil || !strings.Contains(err.Error(), "state has changed") {
		t.Fatalf("stale enabled snapshot restarted: %v", err)
	}
}
