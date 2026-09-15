package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalPackageProductUploadValidatePublish(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	authJSON := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages", strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"8.4.0-test"}`))
	authJSON(req)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create package => %d %s", res.Code, res.Body.String())
	}
	var createPayload struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &createPayload); err != nil || createPayload.Data.PackageID == "" {
		t.Fatalf("packageId отсутствует: err=%v body=%s", err, res.Body.String())
	}
	packageID := createPayload.Data.PackageID

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("path", "mods/example.jar")
	part, err := writer.CreateFormFile("file", "example.jar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("neverlauncher-package-product-840"))
	_ = writer.Close()

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/files", &body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), "mods/example.jar") {
		t.Fatalf("upload file => %d %s", res.Code, res.Body.String())
	}

	// Smoke-test before sign/stage must fail closed.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+packageID+"/smoke-test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("smoke-test до stage должен быть отклонён => %d %s", res.Code, res.Body.String())
	}

	for _, path := range []string{
		"/api/v1/packages/" + packageID + "/validate",
		"/api/v1/packages/" + packageID + "/sign",
		"/api/v1/packages/" + packageID + "/stage",
		"/api/v1/packages/" + packageID + "/smoke-test",
		"/api/v1/packages/" + packageID + "/publish",
	} {
		req = httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "8.4.0") {
			t.Fatalf("%s => %d %s", path, res.Code, res.Body.String())
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/demo-project/profiles/vanilla/manifest?channel=stable", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "mods/example.jar") {
		t.Fatalf("published manifest => %d %s", res.Code, res.Body.String())
	}
}

func TestPublishedPackageIsImmutable(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) }

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages", strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"immutable-v4-test"}`))
	req.Header.Set("Content-Type", "application/json")
	auth(req)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create => %d %s", res.Code, res.Body.String())
	}
	var payload struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	id := payload.Data.PackageID

	upload := func(content string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		_ = w.WriteField("path", "mods/immutable.jar")
		part, _ := w.CreateFormFile("file", "immutable.jar")
		_, _ = part.Write([]byte(content))
		_ = w.Close()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+id+"/files", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		auth(req)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	if rr := upload("before-publish"); rr.Code != http.StatusCreated {
		t.Fatalf("upload => %d %s", rr.Code, rr.Body.String())
	}
	for _, suffix := range []string{"validate", "sign", "stage", "smoke-test", "publish"} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+id+"/"+suffix, nil)
		auth(req)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s => %d %s", suffix, res.Code, res.Body.String())
		}
	}
	if rr := upload("after-publish"); rr.Code != http.StatusConflict {
		t.Fatalf("published upload must be 409 => %d %s", rr.Code, rr.Body.String())
	}
	for _, suffix := range []string{"sign", "stage", "smoke-test", "publish"} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+id+"/"+suffix, nil)
		auth(req)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusConflict {
			t.Fatalf("published %s must be 409 => %d %s", suffix, res.Code, res.Body.String())
		}
	}

	rollbackBody := strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","toVersion":"immutable-v4-test"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/channels/stable/rollback", rollbackBody)
	req.Header.Set("Content-Type", "application/json")
	auth(req)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("immutable rollback => %d %s", res.Code, res.Body.String())
	}
	var rollback struct {
		Data struct {
			TargetVersion   string `json:"targetVersion"`
			RollbackVersion string `json:"rollbackVersion"`
			Status          string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &rollback); err != nil {
		t.Fatal(err)
	}
	if rollback.Data.TargetVersion != "immutable-v4-test" || rollback.Data.RollbackVersion == "" || rollback.Data.RollbackVersion == rollback.Data.TargetVersion || rollback.Data.Status != "rolled-back-as-new-immutable-release" {
		t.Fatalf("unexpected immutable rollback response: %+v", rollback.Data)
	}
}
