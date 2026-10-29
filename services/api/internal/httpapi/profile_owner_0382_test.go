package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOwnerProfileConfigurationAndRevision0382(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	call := func(method, path, body string, want int, fragment string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != want || !strings.Contains(recorder.Body.String(), fragment) {
			t.Fatalf("%s %s => %d %s; want %d and %q", method, path, recorder.Code, recorder.Body.String(), want, fragment)
		}
	}
	project := "/api/v1/admin/projects/owner-profile-0382"
	call(http.MethodPost, "/api/v1/admin/projects", `{"id":"owner-profile-0382","name":"Owner profile"}`, 201, "owner-profile-0382")
	create := `{"id":"fabric","name":"Fabric","description":"Modded","minecraftVersion":"1.21.1","loader":"fabric","loaderVersion":"0.16.14","javaMajor":21,"preset":"modded","isDefault":true}`
	call(http.MethodPost, project+"/profiles", create, 201, `"isDefault":true`)
	call(http.MethodPost, project+"/profiles", create, 409, "profile already exists")
	call(http.MethodPatch, project+"/profiles/fabric", `{"description":"","preset":"","minecraftVersion":"1.21.4","loader":"fabric","loaderVersion":"0.16.14","javaMajor":21,"expectedRevision":1}`, 200, `"isDefault":true`)
	call(http.MethodPatch, project+"/profiles/fabric", `{"minecraftVersion":"1.21.5","expectedRevision":1}`, 409, "revision conflict")
	call(http.MethodGet, "/api/v1/projects/owner-profile-0382/profiles/fabric/revisions", "", 200, `"revision":1`)
	call(http.MethodGet, "/api/v1/projects/owner-profile-0382/profiles/fabric/revisions", "", 200, `"revision":2`)
	call(http.MethodPost, project+"/profiles/fabric/clone", `{"id":"fabric-copy","name":"Fabric copy","sourceRevision":1}`, 201, `"isDefault":false`)
	// Direct package-create must not bypass the configured profile version.
	call(http.MethodPost, "/api/v1/packages", `{"projectId":"owner-profile-0382","profileId":"fabric","channel":"stable","version":"0.1","minecraftVersion":"1.19.4","loader":"fabric"}`, 409, "profile launch mismatch")
}
