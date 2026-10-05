package extensionhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func writePythonFixture0205(t *testing.T, root string, crash bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("python shebang host fixture is unix-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(root, "backend", "extension")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	crashLine := ""
	if crash {
		crashLine = "sys.exit(17)"
	}
	script := `#!/usr/bin/env python3
import json, os, sys, threading, time, urllib.request
url=os.environ["NEVERLAUNCHER_EXTENSION_HOST_URL"]
token=os.environ["NEVERLAUNCHER_EXTENSION_HOST_TOKEN"]
headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"}
def post(path,obj):
    req=urllib.request.Request(url+path,data=json.dumps(obj).encode(),headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=2) as r: return r.read()
post("/v1/hello",{"protocolVersion":"1.0","extensionId":os.environ["NEVERLAUNCHER_EXTENSION_ID"],"instanceId":os.environ["NEVERLAUNCHER_EXTENSION_INSTANCE_ID"],"pid":os.getpid()})
post("/v1/log",{"level":"info","message":"fixture-online secret="+str("NEVERLAUNCHER_DATABASE_DSN" in os.environ).lower()})
post("/v1/capabilities/project.get",{"projectId":"demo-project"})
print("stdout-ready", flush=True)
` + crashLine + `
while True:
    time.sleep(0.15)
    post("/v1/heartbeat",{})
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func hostFixtureInstall0205(t *testing.T, repo repository.Repository, root string, id string, crash bool) model.ExtensionInstall {
	t.Helper()
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Host fixture", Version: "1.0.0", Publisher: "test.publisher", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}, Permissions: []string{"project:read"}}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	current, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", id)
	if err != nil {
		t.Fatal(err)
	}
	writePythonFixture0205(t, current, crash)
	return model.ExtensionInstall{ExtensionID: id, Scope: "global", CurrentVersion: "1.0.0", DesiredVersion: "1.0.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, Generation: 2, CurrentPackageIdentity: strings.Repeat("a", 64), PackageIdentity: strings.Repeat("a", 64)}
}

func TestExtensionHostRealProcessProtocolAndSanitizedEnvironment0205(t *testing.T) {
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://example.test")
	store := storage.NewLocalStorage(filepath.Join(t.TempDir(), "storage"))
	install := hostFixtureInstall0205(t, repo, root, "example.host", false)
	t.Setenv("NEVERLAUNCHER_DATABASE_DSN", "postgres://must-not-leak")
	host := New(Config{ExtensionRoot: root, StartupTimeout: 4 * time.Second, HeartbeatTimeout: 2 * time.Second, StopTimeout: 2 * time.Second, MaxMemoryBytes: 128 << 20, MaxProcesses: 4, RestartBackoff: 50 * time.Millisecond}, repo, store)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	if err := host.StartInstallation(context.Background(), install); err != nil {
		t.Fatalf("StartInstallation: %v", err)
	}
	st, err := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "running" || !st.Healthy || st.PID <= 0 {
		t.Fatalf("unexpected host status: %#v", st)
	}
	deadline := time.Now().Add(2 * time.Second)
	foundProtocol, foundStdout := false, false
	for time.Now().Before(deadline) {
		logs, _ := host.Logs(Key{ExtensionID: install.ExtensionID, Scope: "global"}, 100)
		for _, entry := range logs {
			if strings.Contains(entry.Message, "fixture-online secret=false") {
				foundProtocol = true
			}
			if strings.Contains(entry.Message, "stdout-ready") {
				foundStdout = true
			}
		}
		if foundProtocol && foundStdout {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !foundProtocol || !foundStdout {
		t.Fatalf("expected protocol/stdout logs: protocol=%v stdout=%v", foundProtocol, foundStdout)
	}
	if err := host.Stop(context.Background(), Key{ExtensionID: install.ExtensionID, Scope: "global"}); err != nil {
		t.Fatal(err)
	}
	st, _ = host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	if st.State != "stopped" {
		t.Fatalf("expected stopped, got %#v", st)
	}
}

func TestExtensionHostCrashLoopDetection0205(t *testing.T) {
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://example.test")
	store := storage.NewLocalStorage(filepath.Join(t.TempDir(), "storage"))
	install := hostFixtureInstall0205(t, repo, root, "example.crashhost", true)
	// Auto-restart re-reads persistent state, so persist an enabled lifecycle state.
	_, err := repo.TransitionExtensionInstall(context.Background(), model.ExtensionLifecycleTransition{ExtensionID: install.ExtensionID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "enable", Source: "test", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: root, StartupTimeout: 3 * time.Second, HeartbeatTimeout: 2 * time.Second, StopTimeout: time.Second, CrashLimit: 2, CrashWindow: 10 * time.Second, RestartBackoff: 40 * time.Millisecond, MaxMemoryBytes: 128 << 20, MaxProcesses: 4}, repo, store)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	err = host.StartInstallation(context.Background(), install)
	if err != nil && !strings.Contains(err.Error(), "exited") {
		t.Fatalf("initial start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, e := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
		if e == nil && st.State == "crashloop" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	t.Fatalf("host did not enter crashloop: %#v", st)
}

func TestSafeEntrypointRejectsSymlink0205(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "extension")); err != nil {
		t.Fatal(err)
	}
	if _, err := safeEntrypoint(root, "extension"); err == nil {
		t.Fatal("symlink entrypoint must be rejected")
	}
}

func TestSanitizedEnvironmentNeverForwardsSecrets0205(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_DATABASE_DSN", "secret")
	t.Setenv("NEVERLAUNCHER_AUTH_TOKEN_SECRET", "secret2")
	env := sanitizedEnvironment(map[string]string{"NEVERLAUNCHER_EXTENSION_HOST_TOKEN": "token"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "DATABASE_DSN") || strings.Contains(joined, "AUTH_TOKEN_SECRET") {
		t.Fatal("backend secrets leaked to extension environment")
	}
	if !strings.Contains(joined, "NEVERLAUNCHER_EXTENSION_HOST_TOKEN=token") {
		t.Fatal("host token missing")
	}
}

func TestStartRequiresEnabledState0205(t *testing.T) {
	host := New(Config{}, repository.NewMemoryRepository("http://example.test"), storage.NewLocalStorage(t.TempDir()))
	err := host.StartInstallation(context.Background(), model.ExtensionInstall{ExtensionID: "example.disabled", CurrentState: model.ExtensionInstallStateDisabled})
	if err == nil || errors.Is(err, ErrNoBackendTarget) {
		t.Fatalf("disabled extension start should fail before target resolution: %v", err)
	}
}

func TestEventSubscriptionPermissionBoundary0206(t *testing.T) {
	s := New(Config{ExtensionRoot: t.TempDir()}, repository.NewMemoryRepository("http://localhost"), storage.NewLocalStorage(t.TempDir()))
	st := &processState{permissions: map[string]struct{}{"events:subscribe": {}, "project:read": {}}}
	if err := s.validateEventPermission0206(st, "project.saved", model.ExtensionEventModeAsync); err != nil {
		t.Fatalf("async permission rejected: %v", err)
	}
	if err := s.validateEventPermission0206(st, "project.before-save", model.ExtensionEventModeSync); err == nil {
		t.Fatal("sync subscription accepted without events:sync")
	}
	st.permissions["events:sync"] = struct{}{}
	if err := s.validateEventPermission0206(st, "project.before-save", model.ExtensionEventModeSync); err != nil {
		t.Fatalf("sync permission rejected: %v", err)
	}
	if err := s.validateEventPermission0206(st, "audit.event.created", model.ExtensionEventModeAsync); err == nil {
		t.Fatal("audit subscription accepted without audit:read")
	}
}

func TestValidateCallbackURLLoopbackOnly0206(t *testing.T) {
	for _, raw := range []string{"https://127.0.0.1:9000", "http://example.com:9000", "http://localhost:9000", "http://127.0.0.1:9000/path", "http://127.0.0.1"} {
		if _, err := validateCallbackURL0206(raw); err == nil {
			t.Fatalf("unsafe callback URL accepted: %s", raw)
		}
	}
	if got, err := validateCallbackURL0206("http://127.0.0.1:9000"); err != nil || got != "http://127.0.0.1:9000" {
		t.Fatalf("valid loopback callback rejected: got=%q err=%v", got, err)
	}
}
