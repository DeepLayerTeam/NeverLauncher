package extensionhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Проверяет настоящий локальный аутентифицированный Host Broker, реальные объекты
// репозитория, живой отзыв возможностей и изоляцию проектов, а не фиктивные
// маршруты.
func TestJavaBackendServicesBroker0484(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://example.test")
	if _, err := repo.SaveProject(model.Project{ID: "other-project", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	ext := "org.backend0484"
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: ext, Name: "Backend", Version: "1.0.0", Publisher: "test", API: "1.0",
		Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/java-host.jar"}}, Permissions: []string{"project:read", "release:read"}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"project:read", "release:read"} {
		if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: ext, Scope: "project", ScopeID: "demo-project", Permission: permission, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	job, _, err := repo.EnqueueDurableJob(ctx, model.DurableJob{Kind: "publish", ActorType: "user", ActorID: "private-actor",
		Action: "release:publish", ProjectID: "demo-project", ResourceType: "release", ResourceID: "vanilla",
		IdempotencyKey: "job0484", Payload: json.RawMessage(`{"secret":"do-not-return"}`)}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	if err := host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Close(shutdown)
	})
	st := &processState{key: Key{ExtensionID: ext, Scope: "project", ScopeID: "demo-project"},
		install:  model.ExtensionInstall{ExtensionID: ext, Scope: "project", ScopeID: "demo-project", CurrentVersion: "1.0.0"},
		manifest: manifest, token: "java-service-auth-token", instanceID: "java-service-test", state: "running"}
	host.mu.Lock()
	host.tokens[st.token] = st
	host.mu.Unlock()
	request := func(capability string, payload map[string]any) (int, map[string]any) {
		t.Helper()
		bytesBody, e := json.Marshal(payload)
		if e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/"+capability, bytes.NewReader(bytesBody))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+st.token)
		req.Header.Set("Content-Type", "application/json")
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		var response map[string]any
		if res.StatusCode == 200 {
			if e = json.Unmarshal(body, &response); e != nil {
				t.Fatalf("Некорректный JSON: %s %v", body, e)
			}
		}
		return res.StatusCode, response
	}
	for _, capability := range []string{"profile.list", "channel.list", "release.page", "job.get", "profile.get", "channel.get", "release.get"} {
		// Для некоторых запросов нужны явные идентификаторы сущностей.
		payload := map[string]any{"projectId": "demo-project", "offset": 0, "limit": 1, "name": "stable", "profileId": "vanilla"}
		if capability == "job.get" {
			payload["name"] = job.ID
		}
		if capability == "release.get" {
			payload["name"] = "demo-project-vanilla-3.4.0"
		}
		status, out := request(capability, payload)
		if status != 200 {
			t.Fatalf("%s expected 200 got %d", capability, status)
		}
		if len(out) == 0 {
			t.Fatalf("%s empty response", capability)
		}
		if capability == "job.get" {
			value, ok := out["job"].(map[string]any)
			if !ok {
				t.Fatalf("bad job envelope %v", out)
			}
			for _, sensitive := range []string{"payload", "result", "actorId", "leaseToken", "lastError"} {
				if _, found := value[sensitive]; found {
					t.Fatalf("sensitive field leaked: %s", sensitive)
				}
			}
			if value["projectId"] != "demo-project" {
				t.Fatalf("Задание связано с неверным проектом: %v", value)
			}
		}
	}
	for _, capability := range []string{"profile.list", "channel.list", "release.page", "job.get", "project.get"} {
		payload := map[string]any{"projectId": "other-project", "name": job.ID}
		if status, _ := request(capability, payload); status != http.StatusForbidden {
			t.Fatalf("cross-project %s allowed: %d", capability, status)
		}
	}
	if status, _ := request("project.list", map[string]any{}); status != http.StatusForbidden {
		t.Fatalf("project-scoped enumeration allowed: %d", status)
	}
	if status, _ := request("profile.list", map[string]any{"projectId": "demo-project", "offset": -1}); status != 400 {
		t.Fatalf("invalid pagination allowed: %d", status)
	}
	if err := repo.RevokeExtensionPermission(ctx, ext, "project", "demo-project", "project:read"); err != nil {
		t.Fatal(err)
	}
	if status, _ := request("profile.list", map[string]any{"projectId": "demo-project"}); status != http.StatusForbidden {
		t.Fatalf("revoked project permission ignored: %d", status)
	}
	// release:read не зависит от project:read.
	if status, _ := request("channel.list", map[string]any{"projectId": "demo-project"}); status != 200 {
		t.Fatalf("release grant lost after project revoke: %d", status)
	}
	if err := repo.RevokeExtensionPermission(ctx, ext, "project", "demo-project", "release:read"); err != nil {
		t.Fatal(err)
	}
	if status, _ := request("channel.list", map[string]any{"projectId": "demo-project"}); status != 403 {
		t.Fatalf("revoked release permission ignored: %d", status)
	}
	// Расширение с явно глобальной областью и явным глобальным разрешением может
	// перечислять проекты.
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: ext, Scope: "global", Permission: "project:read", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	global := &processState{key: Key{ExtensionID: ext, Scope: "global"},
		install:  model.ExtensionInstall{ExtensionID: ext, Scope: "global", CurrentVersion: "1.0.0"},
		manifest: manifest, token: "java-global-token", instanceID: "java-global", state: "running"}
	host.mu.Lock()
	host.tokens[global.token] = global
	host.mu.Unlock()
	req, e := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/project.list", bytes.NewReader([]byte(`{"offset":0,"limit":1}`)))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+global.token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var values map[string]any
	if e = json.NewDecoder(resp.Body).Decode(&values); e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 200 || len(values["items"].([]any)) != 1 || values["nextOffset"] == nil {
		t.Fatalf("global page not returned: status=%d response=%v", resp.StatusCode, values)
	}
	if err := repo.RevokeExtensionPermission(ctx, ext, "global", "", "project:read"); err != nil {
		t.Fatal(err)
	}
	req2, e := http.NewRequest(http.MethodPost, host.baseURL+"/v1/capabilities/project.list", bytes.NewReader([]byte(`{"offset":0,"limit":1}`)))
	if e != nil {
		t.Fatal(e)
	}
	req2.Header.Set("Authorization", "Bearer "+global.token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, e := http.DefaultClient.Do(req2)
	if e != nil {
		t.Fatal(e)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Fatalf("global grant revocation ignored: %d", resp2.StatusCode)
	}
}
