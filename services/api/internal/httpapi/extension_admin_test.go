package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestAdminHTMLHardening0208(t *testing.T) {
	html := hardenAdminHTML0208("<!doctype html><html><head><title>x</title></head><body><script>window.ready=true</script></body></html>")
	for _, token := range []string{"Content-Security-Policy", "connect-src 'none'", "object-src 'none'", "form-action 'none'"} {
		if !strings.Contains(html, token) {
			t.Fatalf("В защищённом HTML отсутствует %q", token)
		}
	}
}

func TestSafeAdminEntrypoint0208RejectsSymlinkAndTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := safeAdminEntrypoint0208(root, "index.html"); err != nil {
		t.Fatalf("Отклонена допустимая точка входа: %v", err)
	}
	if _, err := safeAdminEntrypoint0208(root, "../outside.html"); err == nil {
		t.Fatal("допущен выход за пределы разрешённого пути")
	}
	if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err == nil {
		if _, err := safeAdminEntrypoint0208(root, "link.html"); err == nil {
			t.Fatal("Принята точка входа через символьную ссылку")
		}
	}
}

func TestAdminProjectScope0208DoesNotEscapeInstallProject(t *testing.T) {
	projectInstall := model.ExtensionInstall{Scope: "project", ScopeID: "project-a"}
	if !adminExtensionProjectAllowed0208(projectInstall, "project-a") {
		t.Fatal("Отклонён собственный проект")
	}
	if adminExtensionProjectAllowed0208(projectInstall, "project-b") {
		t.Fatal("Расширение с ограничением по проекту получило доступ к другому проекту")
	}
	if adminExtensionProjectAllowed0208(projectInstall, "") {
		t.Fatal("Пустой проект ошибочно принят")
	}
	globalInstall := model.ExtensionInstall{Scope: "global"}
	if !adminExtensionProjectAllowed0208(globalInstall, "project-b") {
		t.Fatal("Глобальный обработчик доступа расширения отклонил конкретный проект")
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
		t.Fatalf("Код состояния=%d, тело ответа=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "connect-src 'none'") || !strings.Contains(rec.Body.String(), "parent.postMessage") {
		t.Fatalf("Неожиданное тело ответа: %s", rec.Body.String())
	}
}

// Проверка русских сообщений жизненного цикла и совместимости со старыми версиями.
func TestLifecycleLocalizedConflictStatus(t *testing.T) {
	cases := []struct {
		message string
		status  int
	}{
		{"Расширение example уже установлено; используйте обновление", http.StatusConflict},
		{"Операция жизненного цикла расширения уже заблокирована: global/example", http.StatusConflict},
		{"Расширение не активировано; используйте установку", http.StatusConflict},
		{"Расширение не установлено", http.StatusConflict},
		{"Нет резервной копии расширения, пригодной для восстановления", http.StatusConflict},
		{"Отозванную версию из реестра устанавливать нельзя", http.StatusConflict},
		{"extension not installed", http.StatusConflict},
		{"Некорректное значение: ID расширения", http.StatusBadRequest},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		writeLifecycleError0204(w, errors.New(tc.message))
		if w.Code != tc.status {
			t.Errorf("Сообщение %q: получен статус %d, ожидался %d", tc.message, w.Code, tc.status)
		}
	}
}
