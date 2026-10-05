package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestExtensionHostAdminList0205(t *testing.T) {
	repo := repository.NewMemoryRepository("http://example.test")
	store := storage.NewLocalStorage(filepath.Join(t.TempDir(), "storage"))
	host := extensionhost.New(extensionhost.Config{ExtensionRoot: t.TempDir()}, repo, store)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = host.Close(ctx)
	})
	srv := Server{Repo: repo, Storage: store, ExtensionHost: host}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/extension-hosts", nil)
	rec := httptest.NewRecorder()
	srv.extensionHosts0205(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body == "" || !containsAll0205(body, "protocolVersion", "resourceIsolation", "items") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestExtensionHostAdminDisabled0205(t *testing.T) {
	srv := Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/extension-hosts", nil)
	rec := httptest.NewRecorder()
	srv.extensionHosts0205(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func containsAll0205(s string, values ...string) bool {
	for _, v := range values {
		if !strings.Contains(s, v) {
			return false
		}
	}
	return true
}
