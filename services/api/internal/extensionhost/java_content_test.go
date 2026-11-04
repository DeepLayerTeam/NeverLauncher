package extensionhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func TestJavaContentRPC0486(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "org.content0486"
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Content", Publisher: "test", Version: "1.0.0", API: "1.0",
		Permissions: []string{"release:read", "release:prepare"}, Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/content.jar"}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	install, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: id, Scope: "project", ScopeID: "project-a", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
		Enabled: true, Operation: "install", ExpectedGeneration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	st := &processState{key: Key{ExtensionID: id, Scope: "project", ScopeID: "project-a"},
		install: install, manifest: manifest, state: "running", javaHost: true, callbackToken: "token"}
	attempts := 0
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// Недопустимый ID вызывает отказ ПОСЛЕ доставки; так проверяется настоящая
		// предварительная проверка.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"protocolVersion": "1.0", "requestId": "wrong", "ok": true, "result": map[string]any{"asset": map[string]any{"projectId": "project-a"}}})
	}))
	defer cb.Close()
	st.callbackURL = cb.URL
	host.processes[st.key.String()] = st
	projectA := json.RawMessage(`{"projectId":"project-a","path":"example.jar"}`)
	projectB := json.RawMessage(`{"projectId":"project-b","path":"example.jar"}`)
	// Нет разрешения выпуска: работающая доверенная JVM никогда не должна получать
	// обратный вызов.
	if _, e := host.CallJavaRPC0304(ctx, st.key, "content.source.resolve", projectA); e == nil || !strings.Contains(e.Error(), "permission") {
		t.Fatalf("ungranted content RPC: %v", e)
	}
	if attempts != 0 {
		t.Fatalf("ungranted callback reached JVM: %d", attempts)
	}
	if _, e := host.CallJavaRPC0304(ctx, st.key, "content.source.resolve", projectB); e == nil || !strings.Contains(e.Error(), "scope") {
		t.Fatalf("cross-project content RPC: %v", e)
	}
	if attempts != 0 {
		t.Fatal("cross-project callback reached JVM")
	}
	for _, permission := range []string{"release:read", "release:prepare"} {
		if _, e := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: id, Scope: "project", ScopeID: "project-a", Permission: permission, GrantedBy: "test"}); e != nil {
			t.Fatal(e)
		}
	}
	for _, method := range []string{"content.source.resolve", "content.texture.resolve", "content.delivery.resolve", "content.metadata.enrich", "content.package.prepare"} {
		before := attempts
		_, _ = host.CallJavaRPC0304(ctx, st.key, method, projectA)
		if attempts != before+1 {
			t.Fatalf("granted %s callback not reached: attempts=%d", method, attempts)
		}
	}
	if _, e := host.CallJavaRPC0304(ctx, st.key, "content.publish.unsigned", projectA); e == nil || !strings.Contains(e.Error(), "unsupported") {
		t.Fatalf("unlisted content method accepted: %v", e)
	}
	if e := repo.RevokeExtensionPermission(ctx, id, "project", "project-a", "release:prepare"); e != nil {
		t.Fatal(e)
	}
	before := attempts
	if _, e := host.CallJavaRPC0304(ctx, st.key, "content.package.prepare", projectA); e == nil || !strings.Contains(e.Error(), "permission") {
		t.Fatalf("revoked prepare still allowed: %v", e)
	}
	if attempts != before {
		t.Fatal("revoked preparation reached JVM")
	}
	// Метаданные только на чтение допускаются независимо от подготовки пакета.
	_, _ = host.CallJavaRPC0304(ctx, st.key, "content.metadata.enrich", projectA)
	if attempts != before+1 {
		t.Fatal("release:read unexpectedly revoked with prepare")
	}
	if e := repo.RevokeExtensionPermission(ctx, id, "project", "project-a", "release:read"); e != nil {
		t.Fatal(e)
	}
	before = attempts
	if _, e := host.CallJavaRPC0304(ctx, st.key, "content.delivery.resolve", projectA); e == nil || !strings.Contains(e.Error(), "permission") {
		t.Fatalf("revoked content read: %v", e)
	}
	if attempts != before {
		t.Fatal("revoked delivery reached JVM")
	}
}
