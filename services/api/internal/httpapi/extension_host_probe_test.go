package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Реальная проверка не должна сводиться к успешному чтению статуса. Отсутствующая
// или остановленная Java-установка либо отключённый хост никогда не считаются
// исправными.
func TestJavaIntegrationProbe0491RejectsAbsentHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/extension-hosts/example.java/probe", nil)
	req.SetPathValue("extensionId", "example.java")
	rec := httptest.NewRecorder()
	(Server{}).extensionHostProbe0491(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled probe status=%d", rec.Code)
	}

	repo := repository.NewMemoryRepository("http://example.test")
	host := extensionhost.New(extensionhost.Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(filepath.Join(t.TempDir(), "storage")))
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	rec = httptest.NewRecorder()
	(Server{Repo: repo, ExtensionHost: host}).extensionHostProbe0491(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("missing running JVM accepted; status=%d body=%s", rec.Code, rec.Body.String())
	}
}
