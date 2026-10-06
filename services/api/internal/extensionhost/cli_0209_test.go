package extensionhost

import (
	"context"
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

func TestCLIExtensionRunsThroughAuthenticatedHostProtocol0209(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python shebang fixture is unix-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://localhost")
	store := storage.NewLocalStorage(t.TempDir())
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.cli", Name: "CLI", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "cli", Entrypoint: "cli/tool"}}, Permissions: []string{"cli:contribute", "project:read"}, CLI: &model.ExtensionCLIContributions{Namespace: "ops", Commands: []model.ExtensionCLICommand{{Name: "status"}}}}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"cli:contribute", "project:read"} {
		if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: p, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(payload, "cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env python3
import json,os,sys,urllib.request
base=os.environ["NEVERLAUNCHER_EXTENSION_HOST_URL"]; token=os.environ["NEVERLAUNCHER_EXTENSION_HOST_TOKEN"]
def post(path,obj):
 data=json.dumps(obj).encode(); req=urllib.request.Request(base+path,data=data,headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},method="POST"); return urllib.request.urlopen(req,timeout=2).read()
post("/v1/hello",{"protocolVersion":"1.0","extensionId":os.environ["NEVERLAUNCHER_EXTENSION_ID"],"instanceId":os.environ["NEVERLAUNCHER_EXTENSION_INSTANCE_ID"],"pid":os.getpid()})
print(json.dumps({"command":sys.argv[1],"target":os.environ.get("NEVERLAUNCHER_EXTENSION_TARGET"),"dbSecretPresent":"NEVERLAUNCHER_DATABASE_DSN" in os.environ}))
`
	if err := os.WriteFile(filepath.Join(payload, "cli", "tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	install := model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", CurrentVersion: "1.0.0", DesiredVersion: "1.0.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, Generation: 1}
	t.Setenv("NEVERLAUNCHER_DATABASE_DSN", "must-not-leak")
	host := New(Config{ExtensionRoot: root, StartupTimeout: 3 * time.Second, MaxMemoryBytes: 128 << 20, MaxProcesses: 4}, repo, store)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	result, err := host.RunCLI0209(context.Background(), install, []string{"status"})
	if err != nil {
		t.Fatalf("RunCLI0209: %v / %#v", err, result)
	}
	if result.ExitCode != 0 || !strings.Contains(result.Stdout, `"target": "cli"`) || !strings.Contains(result.Stdout, `"dbSecretPresent": false`) {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestLifecycleStopTerminatesTransientCLI0209(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python shebang fixture is unix-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://localhost")
	store := storage.NewLocalStorage(t.TempDir())
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.cli-stop", Name: "CLI Stop", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "cli", Entrypoint: "cli/tool"}}, Permissions: []string{"cli:contribute"}, CLI: &model.ExtensionCLIContributions{Namespace: "stop", Commands: []model.ExtensionCLICommand{{Name: "wait"}}}}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GrantExtensionPermission(context.Background(), model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: "cli:contribute", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	payload, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(payload, "cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env python3
import json,os,time,urllib.request
base=os.environ["NEVERLAUNCHER_EXTENSION_HOST_URL"]; token=os.environ["NEVERLAUNCHER_EXTENSION_HOST_TOKEN"]
data=json.dumps({"protocolVersion":"1.0","extensionId":os.environ["NEVERLAUNCHER_EXTENSION_ID"],"instanceId":os.environ["NEVERLAUNCHER_EXTENSION_INSTANCE_ID"],"pid":os.getpid()}).encode()
req=urllib.request.Request(base+"/v1/hello",data=data,headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},method="POST")
urllib.request.urlopen(req,timeout=2).read()
time.sleep(30)
`
	if err := os.WriteFile(filepath.Join(payload, "cli", "tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	install := model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", CurrentVersion: "1.0.0", DesiredVersion: "1.0.0", CurrentState: model.ExtensionInstallStateEnabled, DesiredState: model.ExtensionInstallStateEnabled, Enabled: true, Generation: 1}
	host := New(Config{ExtensionRoot: root, StartupTimeout: 3 * time.Second, StopTimeout: time.Second, MaxMemoryBytes: 128 << 20, MaxProcesses: 4}, repo, store)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	done := make(chan error, 1)
	go func() { _, err := host.RunCLI0209(context.Background(), install, []string{"wait"}); done <- err }()
	key := Key{ExtensionID: manifest.ID, Scope: "global"}.normalized()
	deadline := time.Now().Add(3 * time.Second)
	for {
		host.mu.RLock()
		count := len(host.transients[key.String()])
		host.mu.RUnlock()
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("transient CLI was not registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := host.Stop(ctx, key); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("transient CLI unexpectedly exited successfully")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunCLI0209 did not return after lifecycle Stop")
	}
}
