package extensionlifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func addDependencyInstall0305(t *testing.T, repo repository.Repository, manifest model.ExtensionManifest, state string) {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	_, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: manifest.ID, Scope: "global", DesiredVersion: manifest.Version, CurrentVersion: manifest.Version, DesiredState: state, CurrentState: state, Enabled: state == model.ExtensionInstallStateEnabled, Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
}
func manifest0305(id, version string) model.ExtensionManifest {
	return model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Manager Test", Version: version, Publisher: "deeplayer.team", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}}
}
func TestJavaManagerDependencyAndReverseProtection0305(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	manager := New(t.TempDir(), 3, repo, nil)
	a := manifest0305("example.a", "1.0.0")
	a.Dependencies = []model.ExtensionDependency{{ID: "example.b", Version: "^1.0.0"}}
	if err := manager.checkGraph0305(ctx, a, Scope{Scope: "global"}, false); err == nil {
		t.Fatal("missing dependency accepted")
	}
	b := manifest0305("example.b", "1.0.0")
	addDependencyInstall0305(t, repo, b, model.ExtensionInstallStateDisabled)
	if err := manager.checkGraph0305(ctx, a, Scope{Scope: "global"}, true); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled dependency accepted: %v", err)
	}
	addDependencyInstall0305(t, repo, a, model.ExtensionInstallStateDisabled)
	if err := manager.checkGraph0305(ctx, manifest0305("example.b", "2.0.0"), Scope{Scope: "global"}, false); err == nil || !strings.Contains(err.Error(), "would break") {
		t.Fatalf("breaking update accepted: %v", err)
	}
}
func TestJavaManagerCycleAndConflicts0305(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	manager := New(t.TempDir(), 3, repo, nil)
	a := manifest0305("example.a", "1.0.0")
	b := manifest0305("example.b", "1.0.0")
	a.Dependencies = []model.ExtensionDependency{{ID: "example.b", Version: "*"}}
	b.Dependencies = []model.ExtensionDependency{{ID: "example.a", Version: "*"}}
	addDependencyInstall0305(t, repo, b, model.ExtensionInstallStateDisabled)
	addDependencyInstall0305(t, repo, a, model.ExtensionInstallStateDisabled)
	if err := manager.checkGraph0305(ctx, a, Scope{Scope: "global"}, false); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle accepted: %v", err)
	}
	a.Dependencies = nil
	a.Conflicts = []model.ExtensionConflict{{ID: "example.b", Version: "*"}}
	if err := manager.checkGraph0305(ctx, a, Scope{Scope: "global"}, false); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("conflict accepted: %v", err)
	}
}
func TestJavaManagerEnableRejectsMissingDependency0305(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	root := t.TempDir()
	manager := New(root, 3, repo, nil)
	manifest := manifest0305("example.protected", "1.0.0")
	manifest.Dependencies = []model.ExtensionDependency{{ID: "example.missing", Version: "^1.0.0"}}
	addDependencyInstall0305(t, repo, manifest, model.ExtensionInstallStateDisabled)
	if err := os.MkdirAll(filepath.Join(currentDir0204(root, Scope{Scope: "global"}, manifest.ID), "backend"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Enable(ctx, manifest.ID, Scope{Scope: "global"})
	if err == nil {
		t.Fatal("enabled extension with missing dependency")
	}
	state, e := repo.GetExtensionInstallState(ctx, manifest.ID, "global", "")
	if e != nil {
		t.Fatal(e)
	}
	if state.CurrentState != model.ExtensionInstallStateDisabled {
		t.Fatal("failed enable changed persistent state")
	}
}
