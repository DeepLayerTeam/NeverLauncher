package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestDesktopEntrypointServedFromEnabledGrantedInstall0209(t *testing.T) {
	repo := repository.NewMemoryRepository("http://localhost")
	ctx := context.Background()
	manifest := model.ExtensionManifest{
		SchemaVersion: "2.0", ID: "example.desktop-ui", Name: "Desktop UI", Version: "1.0.0", Publisher: "example", API: "3.7",
		Targets:     []model.ExtensionTarget{{Kind: "desktop", Entrypoint: "desktop/index.html"}},
		Permissions: []string{"desktop:contribute", "desktop:bridge"},
		Desktop:     &model.ExtensionDesktopContributions{Pages: []model.ExtensionDesktopPage{{ID: "main", Title: "Main"}}},
	}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", Version: manifest.Version, Enabled: true, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"desktop:contribute", "desktop:bridge"} {
		if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: permission, GrantedBy: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	payload, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(payload, "desktop"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "desktop", "index.html"), []byte("<html><head></head><body><script>parent.postMessage('ready','*')</script></body></html>"), 0o640); err != nil {
		t.Fatal(err)
	}
	security, err := extensionsecurity.New(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Config: config.Config{ExtensionRoot: root}, Repo: repo, ExtensionSecurity: security}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/desktop/extensions/example.desktop-ui/ui?scope=global", nil)
	req.SetPathValue("extensionId", manifest.ID)
	rec := httptest.NewRecorder()
	srv.desktopExtensionEntrypoint0209(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, token := range []string{desktopBridgeProtocol0209, "connect-src 'none'", "parent.postMessage"} {
		if !strings.Contains(body, token) {
			t.Fatalf("response missing %q: %s", token, body)
		}
	}
}

func TestDesktopInstallManifestDenyByDefault0209(t *testing.T) {
	repo := repository.NewMemoryRepository("http://localhost")
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.desktop-denied", Name: "Denied", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "desktop", Entrypoint: "desktop/index.html"}}, Permissions: []string{"desktop:contribute"}, Desktop: &model.ExtensionDesktopContributions{Pages: []model.ExtensionDesktopPage{{ID: "main", Title: "Main"}}}}
	if _, err := repo.SaveExtensionVersion(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionInstall(context.Background(), model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", Version: manifest.Version, Enabled: true, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	security, err := extensionsecurity.New(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Repo: repo, ExtensionSecurity: security}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, _, err := srv.desktopInstallManifest0209(req, manifest.ID, "global", ""); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("deny-by-default not enforced: %v", err)
	}
}
