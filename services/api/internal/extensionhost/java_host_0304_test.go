package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func TestJavaJarRejectsUnsignedExecutableSubstitution0304(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "backend.jar")
	if err := os.WriteFile(path, []byte("not a JAR"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := safeEntrypoint(root, "backend.jar"); err == nil {
		t.Fatal("non-JAR accepted")
	}
	if err := os.Symlink(path, filepath.Join(root, "link.jar")); err == nil {
		if _, err := safeEntrypoint(root, "link.jar"); err == nil {
			t.Fatal("symlink JAR accepted")
		}
	}
	if _, err := safeEntrypoint(root, "../backend.jar"); err == nil {
		t.Fatal("path traversal accepted")
	}
}
func TestJavaEntrypointParentSymlinkRejected0304(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "real")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "extension")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(root, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := safeEntrypoint(root, "alias/extension"); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestJavaRPCLimitAndMethodWhitelist0304(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://localhost"), storage.NewLocalStorage(t.TempDir()))
	if _, err := s.CallJavaRPC0304(context.Background(), Key{}, "unsafe.eval", nil); err == nil {
		t.Fatal("unexpected method accepted")
	}
	if _, err := s.CallJavaRPC0304(context.Background(), Key{}, "health", json.RawMessage(`{"x":`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := s.CallJavaRPC0304(context.Background(), Key{ExtensionID: "absent"}, "health", nil); !errors.Is(err, ErrHostNotRunning) {
		t.Fatalf("expected not running, got %v", err)
	}
}

// Requires a prebuilt, actual example fat JAR. The CI workflow provides its absolute path.
// Exercises Go supervisor -> Java subprocess -> authenticated hello/ready -> Go->JVM RPC -> CLI.
func javaHostFixture0304(t *testing.T) (*Supervisor, model.ExtensionInstall, Key) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux process-group supervisor test")
	}
	source := os.Getenv("NEVERLAUNCHER_TEST_JAVA_HOST_JAR")
	if source == "" {
		t.Skip("set NEVERLAUNCHER_TEST_JAVA_HOST_JAR to the built Java host example")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("Java 17+ runtime not installed")
	}
	bytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "org.example.java-host"
	pkg, err := os.ReadFile(filepath.Join("../../../..", "examples", "extensions", "java-host", "launcher-extension.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest model.ExtensionManifest
	if err := json.Unmarshal(pkg, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: id, Scope: "global", Permission: "cli:contribute", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	dir, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "backend"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backend", "java-host.jar"), bytes, 0600); err != nil {
		t.Fatal(err)
	}
	install := model.ExtensionInstall{ExtensionID: id, Scope: "global", CurrentVersion: "0.1.0", DesiredVersion: "0.1.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, Generation: 1, CurrentPackageIdentity: strings.Repeat("a", 64), PackageIdentity: strings.Repeat("a", 64)}
	host := New(Config{ExtensionRoot: root, StartupTimeout: 12 * time.Second, HeartbeatTimeout: 6 * time.Second, StopTimeout: 3 * time.Second, CapabilityTimeout: 500 * time.Millisecond, MaxMemoryBytes: 1024 << 20, MaxProcesses: 4, RestartBackoff: time.Second}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	key := Key{ExtensionID: id, Scope: "global"}
	return host, install, key
}
func TestJavaHostSubprocessRPCAndCLI0304(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	status, err := host.Get(key)
	if err != nil || !status.Healthy || status.State != "running" || status.PID <= 0 {
		t.Fatalf("unexpected Go JVM status: %#v: %v", status, err)
	}
	payload, err := host.CallJavaRPC0304(ctx, key, "health", nil)
	if err != nil {
		t.Fatal(err)
	}
	var health struct {
		State      string `json:"state"`
		Responsive bool   `json:"responsive"`
	}
	if err := json.Unmarshal(payload, &health); err != nil || health.State != "RUNNING" || !health.Responsive {
		t.Fatalf("invalid Java health: %s %v", payload, err)
	}
	payload, err = host.CallJavaRPC0304(ctx, key, "command.invoke", json.RawMessage(`{"command":"echo","payload":{"ping":17}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"ping":17`) {
		t.Fatalf("unexpected typed Java RPC result: %s", payload)
	}
	res, err := host.RunCLI0209(ctx, install, []string{"status"})
	if err != nil {
		t.Fatalf("Java CLI: %v stdout=%s stderr=%s", err, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, `"running":true`) {
		t.Fatalf("Java CLI did not execute start(): %s", res.Stdout)
	}
	if err := host.Stop(ctx, key); err != nil {
		t.Fatal(err)
	}
}
func TestJavaHostHungCallbacksDoNotBlockGoSupervisor0304(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = host.CallJavaRPC0304(ctx, key, "command.invoke", json.RawMessage(`{"command":"hang","payload":{}}`))
		}()
	}
	wg.Wait()
	deadline := time.After(19 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, _ := host.Get(key)
		if state.State == "crashed" || state.State == "crashloop" {
			if !strings.Contains(state.LastError, "Java RPC unresponsive") {
				t.Fatalf("unexpected failure: %v", state.LastError)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("hung JVM was not terminated by Go supervisor: %+v", state)
		}
	}
}
