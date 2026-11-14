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

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func writePythonFixture0205(t *testing.T, root string, crash bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Тестовый хост с Python shebang работает только в Unix")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python 3 недоступен")
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
url=os.environ["LAUNCHER_EXTENSION_HOST_URL"]
token=os.environ["LAUNCHER_EXTENSION_HOST_TOKEN"]
headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"}
def post(path,obj):
    req=urllib.request.Request(url+path,data=json.dumps(obj).encode(),headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=2) as r: return r.read()
post("/v1/hello",{"protocolVersion":"1.0","extensionApiVersion":os.environ["LAUNCHER_EXTENSION_API_VERSION"],"extensionId":os.environ["LAUNCHER_EXTENSION_ID"],"instanceId":os.environ["LAUNCHER_EXTENSION_INSTANCE_ID"],"pid":os.getpid()})
post("/v1/log",{"level":"info","message":"fixture-online secret="+str("LAUNCHER_DATABASE_DSN" in os.environ).lower()})
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
	if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: id, Scope: "global", Permission: "project:read", GrantedBy: "test"}); err != nil {
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
	t.Setenv("LAUNCHER_DATABASE_DSN", "postgres://must-not-leak")
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
		t.Fatalf("Ошибка запуска установки: %v", err)
	}
	st, err := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "running" || !st.Healthy || st.PID <= 0 {
		t.Fatalf("Неожиданный статус хоста: %#v", st)
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
		t.Fatalf("Ожидались журналы протокола и стандартного вывода: протокол=%v stdout=%v", foundProtocol, foundStdout)
	}
	if err := host.Stop(context.Background(), Key{ExtensionID: install.ExtensionID, Scope: "global"}); err != nil {
		t.Fatal(err)
	}
	st, _ = host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	if st.State != "stopped" {
		t.Fatalf("Ожидалась остановка, получено: %#v", st)
	}
}

func TestExtensionHostCrashLoopDetection0205(t *testing.T) {
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://example.test")
	store := storage.NewLocalStorage(filepath.Join(t.TempDir(), "storage"))
	install := hostFixtureInstall0205(t, repo, root, "example.crashhost", true)
	// Автоматический перезапуск повторно читает постоянное состояние, поэтому сохраняйте статус активного жизненного цикла.
	install, err := repo.TransitionExtensionInstall(context.Background(), model.ExtensionLifecycleTransition{ExtensionID: install.ExtensionID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "enable", Source: "test", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: root, StartupTimeout: 3 * time.Second, HeartbeatTimeout: 2 * time.Second, StopTimeout: time.Second, CrashLimit: 2, CrashWindow: 10 * time.Second, RestartBackoff: 40 * time.Millisecond, MaxMemoryBytes: 128 << 20, MaxProcesses: 4}, repo, store)
	crashLoopPersisted := make(chan struct{}, 1)
	host.SetCrashLoopHandler(func(ctx context.Context, key Key, reason string) {
		_, _ = repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: key.ExtensionID, Scope: key.Scope, ScopeID: key.ScopeID, Reason: reason, Source: "crash-loop-test"})
		select {
		case crashLoopPersisted <- struct{}{}:
		default:
		}
	})
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	err = host.StartInstallation(context.Background(), install)
	if err != nil && !strings.Contains(err.Error(), "завершил") {
		t.Fatalf("Первоначальный запуск: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, e := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
		if e == nil && st.State == "crashloop" {
			select {
			case <-crashLoopPersisted:
			case <-time.After(2 * time.Second):
				t.Fatal("Обработчик цикла аварийных завершений не сохранил экстренное отключение")
			}
			if _, err := repo.GetExtensionEmergencyDisable(context.Background(), install.ExtensionID, "global", ""); err != nil {
				t.Fatalf("Отсутствует сохранённое экстренное отключение: %v", err)
			}
			if err := host.StartInstallation(context.Background(), install); err == nil || !strings.Contains(err.Error(), "аварийно отключено") {
				t.Fatalf("Расширение перезапущено после повторных сбоев вопреки аварийному выключателю: %v", err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := host.Get(Key{ExtensionID: install.ExtensionID, Scope: "global"})
	t.Fatalf("Хост не перешёл в состояние циклического сбоя: %#v", st)
}

func TestSafeEntrypointRejectsSymlink0205(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Разрешения символьных ссылок различаются в Windows")
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
		t.Fatal("Точка входа через символьную ссылку должна отклоняться")
	}
}

func TestSanitizedEnvironmentNeverForwardsSecrets0205(t *testing.T) {
	t.Setenv("LAUNCHER_DATABASE_DSN", "secret")
	t.Setenv("LAUNCHER_AUTH_TOKEN_SECRET", "secret2")
	env := sanitizedEnvironment(map[string]string{"LAUNCHER_EXTENSION_HOST_TOKEN": "token"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "DATABASE_DSN") || strings.Contains(joined, "AUTH_TOKEN_SECRET") {
		t.Fatal("Секреты сервера раскрыты в окружении расширения")
	}
	if !strings.Contains(joined, "LAUNCHER_EXTENSION_HOST_TOKEN=token") {
		t.Fatal("Отсутствует токен хоста")
	}
}

func TestStartRequiresEnabledState0205(t *testing.T) {
	host := New(Config{}, repository.NewMemoryRepository("http://example.test"), storage.NewLocalStorage(t.TempDir()))
	err := host.StartInstallation(context.Background(), model.ExtensionInstall{ExtensionID: "example.disabled", CurrentState: model.ExtensionInstallStateDisabled})
	if err == nil || errors.Is(err, ErrNoBackendTarget) {
		t.Fatalf("Запуск отключённого расширения должен блокироваться до разрешения целевой точки: %v", err)
	}
}

func TestEventSubscriptionPermissionBoundary0206(t *testing.T) {
	repo := repository.NewMemoryRepository("http://localhost")
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.events", Name: "events", Version: "1.0.0", Publisher: "test.publisher", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}, Permissions: []string{"events:subscribe", "events:sync", "project:read", "audit:read"}}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"events:subscribe", "project:read"} {
		if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: p, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	s := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	st := &processState{key: Key{ExtensionID: manifest.ID, Scope: "global"}, install: model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", CurrentVersion: "1.0.0"}, manifest: manifest}
	if err := s.validateEventPermission0206(st, "project.saved", model.ExtensionEventModeAsync); err != nil {
		t.Fatalf("Разрешение на асинхронную операцию ошибочно отклонено: %v", err)
	}
	if err := s.validateEventPermission0206(st, "project.before-save", model.ExtensionEventModeSync); err == nil {
		t.Fatal("Разрешена синхронная подписка без права events:sync")
	}
	if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: "events:sync", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.validateEventPermission0206(st, "project.before-save", model.ExtensionEventModeSync); err != nil {
		t.Fatalf("Отклонено разрешение синхронного доступа: %v", err)
	}
	if err := s.validateEventPermission0206(st, "audit.event.created", model.ExtensionEventModeAsync); err == nil {
		t.Fatal("Разрешена подписка на аудит без права audit:read")
	}
}

func TestValidateCallbackURLLoopbackOnly0206(t *testing.T) {
	for _, raw := range []string{"https://127.0.0.1:9000", "http://example.com:9000", "http://localhost:9000", "http://127.0.0.1:9000/path", "http://127.0.0.1"} {
		if _, err := validateCallbackURL0206(raw); err == nil {
			t.Fatalf("Принят небезопасный URL обратного вызова: %s", raw)
		}
	}
	if got, err := validateCallbackURL0206("http://127.0.0.1:9000"); err != nil || got != "http://127.0.0.1:9000" {
		t.Fatalf("Отклонён допустимый локальный обратный вызов: получено=%q ошибка=%v", got, err)
	}
}
