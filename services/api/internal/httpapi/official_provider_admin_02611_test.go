package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestOfficialProviderPolicyGate02611(t *testing.T) {
	repo := &repository.MemoryRepository{}
	server := Server{Repo: repo, Config: config.Config{MinecraftMicrosoftClientID: "11223344-5566-7788-99aa-bbccddeeff00"}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/minecraft/official/browser/config", nil)
	w := httptest.NewRecorder()
	got, ok := server.officialProviderPolicy02611(w, req, "browser")
	if !ok || got.ClientID == "" {
		t.Fatalf("env-backed policy not applied: %d", w.Code)
	}
	got.BrowserEnabled = false
	if _, err := repo.SaveOfficialProvider02611(context.Background(), 0, got, "admin", "disable browser login"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	_, ok = server.officialProviderPolicy02611(w, req, "browser")
	if ok || w.Code != 403 {
		t.Fatalf("browser flow should be forbidden: %v %d", ok, w.Code)
	}
	w = httptest.NewRecorder()
	_, ok = server.officialProviderPolicy02611(w, req, "device")
	if !ok {
		t.Fatalf("device fallback unexpectedly disabled: %d", w.Code)
	}
}
func TestOfficialProviderPayloadValidation02611(t *testing.T) {
	body := `{"expectedRevision":0,"settings":{"clientId":"11223344-5566-7788-99aa-bbccddeeff00","enabled":true,"browserEnabled":true,"deviceEnabled":false,"issuer":"common"},"reason":"invalid issuer"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/official-provider", strings.NewReader(body))
	_, err := readOfficialProviderUpdate02611(httptest.NewRecorder(), req)
	if err == nil {
		t.Fatal("unsupported issuer accepted")
	}
}
