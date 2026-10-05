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

func TestAdminHTMLHardening0208(t *testing.T) {
	html := hardenAdminHTML0208("<!doctype html><html><head><title>x</title></head><body><script>window.ready=true</script></body></html>")
	for _, token := range []string{"Content-Security-Policy", "connect-src 'none'", "object-src 'none'", "form-action 'none'"} {
		if !strings.Contains(html, token) {
			t.Fatalf("hardened HTML missing %q", token)
		}
	}
}

func TestSafeAdminEntrypoint0208RejectsSymlinkAndTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := safeAdminEntrypoint0208(root, "index.html"); err != nil {
		t.Fatalf("valid entrypoint rejected: %v", err)
	}
	if _, err := safeAdminEntrypoint0208(root, "../outside.html"); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err == nil {
		if _, err := safeAdminEntrypoint0208(root, "link.html"); err == nil {
			t.Fatal("symlink entrypoint accepted")
		}
	}
}

func TestAdminProjectScope0208DoesNotEscapeInstallProject(t *testing.T) {
	projectInstall := model.ExtensionInstall{Scope: "project", ScopeID: "project-a"}
	if !adminExtensionProjectAllowed0208(projectInstall, "project-a") {
		t.Fatal("own project rejected")
	}
	if adminExtensionProjectAllowed0208(projectInstall, "project-b") {
		t.Fatal("project-scoped extension escaped into another project")
	}
	if adminExtensionProjectAllowed0208(projectInstall, "") {
		t.Fatal("empty project accepted")
	}
	globalInstall := model.ExtensionInstall{Scope: "global"}
	if !adminExtensionProjectAllowed0208(globalInstall, "project-b") {
		t.Fatal("global extension project access helper rejected a concrete project")
	}
}

func TestAdminEntrypointServedFromEnabledVerifiedInstall0208(t *testing.T) {
	repo := repository.NewMemoryRepository("http://localhost")
	ctx := context.Background()
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.admin-ui", Name: "Admin UI", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.html"}}, Permissions: []string{"ui:contribute"}, Admin: &model.ExtensionAdminContributions{Pages: []model.ExtensionAdminPage{{ID: "main", Title: "Main"}}}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveExtensionInstall(ctx, model.ExtensionInstall{ExtensionID: manifest.ID, Scope: "global", Version: manifest.Version, Enabled: true, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: manifest.ID, Scope: "global", Permission: "ui:contribute", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	payload, err := extensionlifecycle.CurrentPayloadDir(root, "global", "", manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(payload, "admin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "admin", "index.html"), []byte("<html><head></head><body><script>parent.postMessage('ready','*')</script></body></html>"), 0o640); err != nil {
		t.Fatal(err)
	}
	security, err := extensionsecurity.New(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Config: config.Config{ExtensionRoot: root}, Repo: repo, ExtensionSecurity: security}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/extensions/example.admin-ui/ui?scope=global", nil)
	req.SetPathValue("extensionId", manifest.ID)
	rec := httptest.NewRecorder()
	srv.adminExtensionEntrypoint0208(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "connect-src 'none'") || !strings.Contains(rec.Body.String(), "parent.postMessage") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
