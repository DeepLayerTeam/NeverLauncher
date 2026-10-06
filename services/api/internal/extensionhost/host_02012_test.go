package extensionhost

import (
	"context"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestPersistentEmergencyDisableBlocksHostBeforeExecution02012(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	install := model.ExtensionInstall{ExtensionID: "example.killswitch", Scope: "global", CurrentVersion: "1.0.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, CurrentPackageIdentity: "sha256:" + strings.Repeat("a", 64)}
	if _, err := repo.SetExtensionEmergencyDisable(context.Background(), model.ExtensionEmergencyDisable{ExtensionID: install.ExtensionID, Scope: "global", Reason: "incident response", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.StartInstallation(context.Background(), install); err == nil || !strings.Contains(err.Error(), "emergency-disabled") {
		t.Fatalf("emergency-disabled extension reached execution path: %v", err)
	}
}

func TestQuarantinedPackageBlocksHostBeforeExecution02012(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	identity := "sha256:" + strings.Repeat("a", 64)
	install := model.ExtensionInstall{ExtensionID: "example.quarantine", Scope: "global", CurrentVersion: "1.0.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, CurrentPackageIdentity: identity}
	if _, err := repo.SaveExtensionQuarantine(context.Background(), model.ExtensionQuarantineEntry{ID: "q-host", PackageIdentity: identity, ArtifactSHA256: strings.Repeat("b", 64), ExtensionID: install.ExtensionID, Version: install.CurrentVersion, Reason: "malicious fixture"}); err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.StartInstallation(context.Background(), install); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("quarantined extension reached execution path: %v", err)
	}
}

func TestCrashLoopHandlerPersistsKillSwitch02012(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	host := New(Config{CrashLimit: 1, CrashWindow: 10 * time.Second, RestartBackoff: time.Millisecond}, repo, storage.NewLocalStorage(t.TempDir()))
	host.ctx = context.Background()
	persisted := make(chan error, 1)
	host.SetCrashLoopHandler(func(ctx context.Context, key Key, reason string) {
		_, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: key.ExtensionID, Scope: key.Scope, ScopeID: key.ScopeID, Reason: reason, Source: "crash-loop"})
		persisted <- err
	})
	st := &processState{key: Key{ExtensionID: "example.crashloop", Scope: "global"}}
	host.registerCrashAndRestart(st)
	host.registerCrashAndRestart(st)
	select {
	case err := <-persisted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("crash-loop persistence callback was not invoked")
	}
	if _, err := repo.GetExtensionEmergencyDisable(context.Background(), "example.crashloop", "global", ""); err != nil {
		t.Fatalf("persistent crash-loop kill-switch missing: %v", err)
	}
}
