package extensionhost

import (
	"context"
	"encoding/json"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeStoragePersistenceIsolationAndLimits0303(t *testing.T) {
	root := t.TempDir()
	global := runtimeDir0303(root, Key{ExtensionID: "test.example", Scope: "global"})
	project := runtimeDir0303(root, Key{ExtensionID: "test.example", Scope: "project", ScopeID: "p1"})
	other := runtimeDir0303(root, Key{ExtensionID: "other.example", Scope: "global"})
	if global == project || global == other || project == other {
		t.Fatal("scope collision")
	}
	path, err := runtimeFile0303(global, "config", "settings")
	if err != nil {
		t.Fatal(err)
	}
	body := json.RawMessage(`{"enabled":true,"rate":3}`)
	if err := runtimeWrite0303(context.Background(), global, path, body); err != nil {
		t.Fatal(err)
	}
	read, found, err := runtimeRead0303(global, path)
	if err != nil || !found || string(read) != string(body) {
		t.Fatalf("state read %s %v %v", read, found, err)
	}
	if _, found, err := runtimeRead0303(project, filepath.Join(project, filepath.Base(path))); err != nil || found {
		t.Fatalf("cross-scope read: %v %v", found, err)
	}
	if err := runtimeWrite0303(context.Background(), global, path, json.RawMessage(`{"rate":4}`)); err != nil {
		t.Fatal(err)
	}
	read, found, err = runtimeRead0303(global, path)
	if err != nil || !found || string(read) != `{"rate":4}` {
		t.Fatal("atomic overwrite failed")
	}
	if _, err := runtimeFile0303(global, "config", "../../escape"); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := runtimeWrite0303(context.Background(), global, path, json.RawMessage(`{"incomplete":`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if err := runtimeWrite0303(context.Background(), global, path, json.RawMessage(`"`+strings.Repeat("a", runtimeValueLimit0303)+`"`)); err == nil {
		t.Fatal("oversized state accepted")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm()&0077 != 0 {
		t.Fatalf("state file permissions: %v %v", st, err)
	}
}

func TestRuntimeStorageSymlinksRejected0303(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "runtime-data")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	dir := runtimeDir0303(root, Key{ExtensionID: "test.example", Scope: "global"})
	path, _ := runtimeFile0303(dir, "storage", "state")
	if err := runtimeWrite0303(context.Background(), dir, path, json.RawMessage(`{"x":1}`)); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, filepath.Base(dir))); !os.IsNotExist(err) {
		t.Fatal("storage escaped root")
	}
}

func TestRuntimeStoreQuotas0303(t *testing.T) {
	root := t.TempDir()
	dir := runtimeDir0303(root, Key{ExtensionID: "test.example", Scope: "global"})
	value := json.RawMessage(`"` + strings.Repeat("a", 60000) + `"`)
	for i := 0; i < 72; i++ {
		key := string(rune('a'+i/26)) + string(rune('a'+i%26))
		path, _ := runtimeFile0303(dir, "storage", key)
		err := runtimeWrite0303(context.Background(), dir, path, value)
		if i >= 69 {
			if err == nil {
				t.Fatal("expected total quota failure")
			}
			break
		}
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
}

// Real local HTTP broker integration: permission changes are effective immediately,
// even when a caller retains the same authenticated instance token.
func TestRuntimeHTTPPermissions0303(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://example.test")
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "test.runtime", Name: "Runtime", Version: "1.0.0", Publisher: "test", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}, Permissions: []string{"storage:read", "storage:write"}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: "storage:read", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = host.Close(stop)
	})
	st := &processState{key: Key{ExtensionID: manifest.ID, Scope: "global"}, install: model.ExtensionInstall{ExtensionID: manifest.ID, CurrentVersion: "1.0.0"}, manifest: manifest, token: "test-broker-token", instanceID: "instance-1", state: "running"}
	host.mu.Lock()
	host.tokens[st.token] = st
	host.mu.Unlock()
	request := func(capability string, payload string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/"+capability, strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+st.token)
		req.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if code := request("runtime.storage.put", `{"key":"state","value":{"count":1}}`); code != 403 {
		t.Fatalf("write granted without permission: %d", code)
	}
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: "storage:write", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if code := request("runtime.storage.put", `{"key":"state","value":{"count":1}}`); code != 200 {
		t.Fatalf("write denied: %d", code)
	}
	if code := request("runtime.storage.get", `{"key":"state"}`); code != 200 {
		t.Fatalf("read denied: %d", code)
	}
	if err := repo.RevokeExtensionPermission(ctx, manifest.ID, "global", "", "storage:read"); err != nil {
		t.Fatal(err)
	}
	if code := request("runtime.storage.get", `{"key":"state"}`); code != 403 {
		t.Fatalf("revoked read allowed: %d", code)
	}
	if code := request("runtime.storage.put", `{"key":"../../escape","value":true}`); code != 400 {
		t.Fatalf("traversal accepted: %d", code)
	}
	if code := request("runtime.storage.put", `{"key":"state","value":{"count":2}}`); code != 200 {
		t.Fatalf("state overwrite failed: %d", code)
	}
	if code := request("runtime.storage.delete", `{"key":"state"}`); code != 200 {
		t.Fatalf("state deletion failed: %d", code)
	}
	if code := request("runtime.storage.put", `{"key":"state","value":{"count":3}}`); code != 200 {
		t.Fatalf("state restart failed: %d", code)
	}
}
