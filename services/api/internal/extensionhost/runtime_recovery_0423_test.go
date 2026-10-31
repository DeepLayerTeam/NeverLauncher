package extensionhost

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

// Exercise the authenticated broker, not just the file helpers. The second
// Supervisor runs with the same configured durable root but a new HTTP server,
// instance token and process state.
func TestRuntimeBrokerDocumentsSurviveSupervisorRestart0423(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://example.test")
	const id = "test.storage0423"
	manifest := model.ExtensionManifest{
		SchemaVersion: "2.0", ID: id, Name: "Persistence", Version: "1.0.0", Publisher: "test",
		API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}},
		Permissions: []string{"storage:read", "storage:write"},
	}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	for _, permission := range manifest.Permissions {
		if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{
			ExtensionID: id, Scope: "global", Permission: permission, GrantedBy: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		host := New(Config{ExtensionRoot: root}, repo, storage.NewLocalStorage(t.TempDir()))
		if err := host.Start(ctx); err != nil {
			t.Fatal(err)
		}
		token := fmt.Sprintf("restarted-token-%d", attempt)
		st := &processState{
			key:      Key{ExtensionID: id, Scope: "global"},
			install:  model.ExtensionInstall{ExtensionID: id, Scope: "global", CurrentVersion: "1.0.0"},
			manifest: manifest, token: token, instanceID: fmt.Sprintf("instance-%d", attempt), state: "running",
		}
		host.mu.Lock()
		host.tokens[token] = st
		host.mu.Unlock()
		request := func(capability, data string) (int, string) {
			t.Helper()
			req, err := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/"+capability, strings.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			b, err := io.ReadAll(io.LimitReader(response.Body, 4096))
			if err != nil {
				t.Fatal(err)
			}
			return response.StatusCode, string(b)
		}
		switch attempt {
		case 0:
			status, body := request("runtime.storage.put", `{"key":"counter","value":{"count":42}}`)
			if status != 200 {
				t.Fatalf("initial write status=%d %s", status, body)
			}
		case 1:
			status, body := request("runtime.storage.get", `{"key":"counter"}`)
			if status != 200 || !strings.Contains(body, `"count":42`) {
				t.Fatalf("state missing after restart: %d %s", status, body)
			}
			status, body = request("runtime.storage.delete", `{"key":"counter"}`)
			if status != 200 {
				t.Fatalf("delete after restart: %d %s", status, body)
			}
		case 2:
			status, body := request("runtime.storage.get", `{"key":"counter"}`)
			if status != 404 {
				t.Fatalf("deleted key resurrected after restart: %d %s", status, body)
			}
		}
		stop, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := host.Close(stop); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
	}
}
