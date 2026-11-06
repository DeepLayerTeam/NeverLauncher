package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReleaseWorkspaceDraftOwnershipAndResume0218(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	call := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	res := call("POST", "/api/v1/release-drafts", `{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.21.8-test","minecraftVersion":"1.21.1","loader":"vanilla","step":"build","ownerId":"attacker","id":"injected"}`, true)
	if res.Code != 201 {
		t.Fatalf("создание: %d %s", res.Code, res.Body.String())
	}
	var created struct {
		Data struct {
			ID, OwnerID, ProjectID string
			Revision               int64
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.ID == "injected" || created.Data.OwnerID == "attacker" || created.Data.Revision != 1 {
		t.Fatalf("Принят недоверенный идентификатор: %s", res.Body.String())
	}
	id := created.Data.ID
	if res = call("GET", "/api/v1/release-drafts/"+id, "", false); res.Code != 401 {
		t.Fatalf("Несанкционированное чтение=%d", res.Code)
	}
	if res = call("GET", "/api/v1/release-drafts?projectId=demo-project", "", true); res.Code != 200 || !strings.Contains(res.Body.String(), id) {
		t.Fatalf("Список продолжения=%d %s", res.Code, res.Body.String())
	}
	update := fmt.Sprintf(`{"id":%q,"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.21.8-test","minecraftVersion":"1.21.1","loader":"vanilla","step":"verify","revision":1}`, id)
	if res = call("PUT", "/api/v1/release-drafts/"+id, update, true); res.Code != 200 {
		t.Fatalf("сохранение: %d %s", res.Code, res.Body.String())
	}
	if res = call("PUT", "/api/v1/release-drafts/"+id, update, true); res.Code != 409 {
		t.Fatalf("Устаревшая ревизия=%d %s", res.Code, res.Body.String())
	}
	if res = call("GET", "/api/v1/release-drafts/"+id, "", true); res.Code != 200 || !strings.Contains(res.Body.String(), `"revision":2`) {
		t.Fatalf("возобновление: %d %s", res.Code, res.Body.String())
	}
	if res = call("DELETE", "/api/v1/release-drafts/"+id, "", true); res.Code != 200 {
		t.Fatalf("удаление: %d %s", res.Code, res.Body.String())
	}
	if res = call("GET", "/api/v1/release-drafts/"+id, "", true); res.Code != 404 {
		t.Fatalf("После удаления=%d", res.Code)
	}
}

func TestReleaseWorkspaceRejectsForeignPackageBinding0218(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, req)
		return r
	}
	created := post("/api/v1/packages", `{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.21.8-binding"}`)
	if created.Code != 201 {
		t.Fatalf("Создание пакета: %d %s", created.Code, created.Body.String())
	}
	var pkg struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	draft := post("/api/v1/release-drafts", fmt.Sprintf(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"DIFFERENT","packageId":%q}`, pkg.Data.PackageID))
	if draft.Code != 409 {
		t.Fatalf("Принят чужой пакет: %d %s", draft.Code, draft.Body.String())
	}
}

func TestReleaseWorkspacePackageMetadataPersisted0218(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages", strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.21.8-metadata","minecraftVersion":"1.21.1","loader":"fabric"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != 201 {
		t.Fatalf("создание: %d %s", res.Code, res.Body.String())
	}
	var created struct {
		Data struct {
			PackageID string                           `json:"packageId"`
			Minecraft struct{ Version, Loader string } `json:"minecraft"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.Minecraft.Version != "1.21.1" || created.Data.Minecraft.Loader != "fabric" {
		t.Fatalf("Метаданные не сохранены в реальном пакете: %s", res.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/packages/"+created.Data.PackageID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != 200 || !strings.Contains(res.Body.String(), `"loader":"fabric"`) {
		t.Fatalf("Метаданные утеряны: %d %s", res.Code, res.Body.String())
	}
}
