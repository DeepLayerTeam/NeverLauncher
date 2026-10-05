package extensionlifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type failingLifecycleRepo0204 struct {
	repository.Repository
	err error
}

func (r failingLifecycleRepo0204) TransitionExtensionInstall(context.Context, model.ExtensionLifecycleTransition) (model.ExtensionInstall, error) {
	return model.ExtensionInstall{}, r.err
}

func seedLifecycleInstall0204(t *testing.T, repo repository.Repository, id, version, state string) model.ExtensionInstall {
	t.Helper()
	ctx := context.Background()
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Lifecycle Test", Version: version, Publisher: "deeplayer.team", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	item, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: version, CurrentVersion: version, DesiredState: state, CurrentState: state, Enabled: state == model.ExtensionInstallStateEnabled, Operation: "install", Source: "test", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	return item
}
func writeCurrentPayload0204(t *testing.T, root, id, content string) {
	t.Helper()
	current := currentDir0204(root, Scope{Scope: "global"}, id)
	if err := os.MkdirAll(filepath.Join(current, "backend"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "backend", "extension"), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionLifecycleEnableDisableUninstallRollback0204(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://example.test")
	root := t.TempDir()
	manager := New(root, 10, repo, nil)
	id := "example.lifecycle"
	seedLifecycleInstall0204(t, repo, id, "1.0.0", model.ExtensionInstallStateDisabled)
	writeCurrentPayload0204(t, root, id, "v1")
	enabled, err := manager.Enable(ctx, id, Scope{Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.CurrentState != model.ExtensionInstallStateEnabled || enabled.Generation != 2 {
		t.Fatalf("enabled=%+v", enabled)
	}
	disabled, err := manager.Disable(ctx, id, Scope{Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.CurrentState != model.ExtensionInstallStateDisabled || disabled.Generation != 3 {
		t.Fatalf("disabled=%+v", disabled)
	}
	uninstalled, err := manager.Uninstall(ctx, id, Scope{Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if uninstalled.CurrentState != model.ExtensionInstallStateAbsent || uninstalled.Generation != 4 {
		t.Fatalf("uninstalled=%+v", uninstalled)
	}
	if _, err := os.Stat(currentDir0204(root, Scope{Scope: "global"}, id)); !os.IsNotExist(err) {
		t.Fatalf("current still exists after uninstall: %v", err)
	}
	rolled, err := manager.Rollback(ctx, id, Scope{Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.CurrentVersion != "1.0.0" || rolled.CurrentState != model.ExtensionInstallStateDisabled || rolled.Generation != 5 {
		t.Fatalf("rolled=%+v", rolled)
	}
	data, err := os.ReadFile(filepath.Join(currentDir0204(root, Scope{Scope: "global"}, id), "backend", "extension"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "v1" {
		t.Fatalf("restored payload=%q", data)
	}
	if err := manager.VerifyLockfile(ctx, id, Scope{Scope: "global"}); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionLifecycleFilesystemRollbackOnRepositoryFailure0204(t *testing.T) {
	ctx := context.Background()
	baseRepo := repository.NewMemoryRepository("http://example.test")
	root := t.TempDir()
	id := "example.failure"
	before := seedLifecycleInstall0204(t, baseRepo, id, "1.0.0", model.ExtensionInstallStateEnabled)
	writeCurrentPayload0204(t, root, id, "keep-me")
	manager := New(root, 10, failingLifecycleRepo0204{Repository: baseRepo, err: errors.New("forced repository failure")}, nil)
	if _, err := manager.Uninstall(ctx, id, Scope{Scope: "global"}); err == nil || err.Error() != "forced repository failure" {
		t.Fatalf("uninstall error=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(currentDir0204(root, Scope{Scope: "global"}, id), "backend", "extension"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep-me" {
		t.Fatalf("payload changed after failed transaction: %q", data)
	}
	after, err := baseRepo.GetExtensionInstallState(ctx, id, "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation || after.CurrentState != before.CurrentState || after.CurrentVersion != before.CurrentVersion {
		t.Fatalf("repository mutated on failed transaction: before=%+v after=%+v", before, after)
	}
}
