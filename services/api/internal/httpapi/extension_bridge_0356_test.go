package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestDesktopBridgeRevocationAndGeneration0356(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("https://api.example.test")
	manifest := model.ExtensionManifest{
		SchemaVersion: "2.0", ID: "example.desktop-0356", Name: "Desktop", Version: "1.0.0", Publisher: "example", API: "3.7",
		Targets:     []model.ExtensionTarget{{Kind: "desktop", Entrypoint: "desktop/index.html"}},
		Permissions: []string{"desktop:contribute", "desktop:bridge"},
		Desktop:     &model.ExtensionDesktopContributions{Pages: []model.ExtensionDesktopPage{{ID: "main", Title: "Main"}}},
	}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	install, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", Version: manifest.Version, Enabled: true, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, perm := range []string{"desktop:contribute", "desktop:bridge"} {
		if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: perm, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := extensionsecurity.New(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewRuntimeState()
	user := model.User{ID: "user-0356", Email: "owner@example.test", RoleID: "owner", Status: "active"}
	if _, err := repo.SaveUser(user); err != nil {
		t.Fatal(err)
	}
	srv := Server{Repo: repo, State: state, ExtensionSecurity: sec, Config: config.Config{PublicURL: "https://api.example.test", AuthTokenSecret: "012345678901234567890123456789012345", AuthTokenIssuer: "https://issuer.example.test", AuthTokenAudience: "neverlauncher-api"}}
	login := httptest.NewRequest(http.MethodPost, "https://api.example.test/login", nil)
	login.RemoteAddr = "203.0.113.1:12345"
	session, _, err := state.AuthSessions.createWithAuth(user, login, "Desktop", []string{"password"}, "single-factor", time.Now().UTC(), "identity", "local")
	if err != nil {
		t.Fatal(err)
	}
	session, err = state.AuthSessions.bindTrustedDevice121(session.ID, user.ID, "device-0356", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	token, err := srv.issueAccessTokenForSession(user, session)
	if err != nil {
		t.Fatal(err)
	}
	run := func(version string, generation int64, action string) (int, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"protocol": desktopBridgeProtocol0209, "id": "rpc-1", "method": "bridge.authorize", "params": map[string]any{"version": version, "generation": generation, "action": action}})
		req := httptest.NewRequest(http.MethodPost, "https://api.example.test/api/v1/desktop/extensions/example.desktop-0356/rpc?scope=global", bytes.NewReader(body))
		req.SetPathValue("extensionId", manifest.ID)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.requireDesktopExtensionAuth0209(srv.desktopExtensionRPC0209).ServeHTTP(rec, req)
		var result map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid response %v: %s", err, rec.Body.String())
		}
		return rec.Code, result
	}
	check := func(version string, generation int64, action string, want bool) {
		t.Helper()
		status, body := run(version, generation, action)
		data, _ := body["data"].(map[string]any)
		result, _ := data["result"].(map[string]any)
		allowed := status == 200 && result["authorized"] == true
		if allowed != want {
			t.Fatalf("version=%s gen=%d action=%s status=%d body=%v", version, generation, action, status, body)
		}
	}
	check("1.0.0", install.Generation, "tauri.openGameDirectory", true)
	check("1.0.0", install.Generation, "tauri.platform", true)
	check("2.0.0", install.Generation, "tauri.platform", false)
	check("1.0.0", install.Generation+1, "tauri.platform", false)
	check("1.0.0", install.Generation, "tauri.execute", false)
	if err := repo.RevokeExtensionPermission(ctx, manifest.ID, "global", "", "desktop:bridge"); err != nil {
		t.Fatal(err)
	}
	check("1.0.0", install.Generation, "tauri.platform", false)
}
