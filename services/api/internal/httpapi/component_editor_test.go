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

func TestComponentCatalogEditorLifecycle0248(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	invoke := func(method, path string, body []byte, ctype string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	created := invoke("POST", "/api/v1/packages", []byte(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.24.8-graph-test","manifestSchemaVersion":"3.0"}`), "application/json")
	if created.Code != 201 {
		t.Fatalf("v3 create %d: %s", created.Code, created.Body.String())
	}
	var response struct {
		Data struct {
			PackageID             string `json:"packageId"`
			ManifestSchemaVersion string `json:"manifestSchemaVersion"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Data.ManifestSchemaVersion != "3.0" {
		t.Fatalf("package not v3: %v %s", err, created.Body.String())
	}
	id := response.Data.PackageID
	var content bytes.Buffer
	writer := multipart.NewWriter(&content)
	_ = writer.WriteField("path", "mods/sodium.jar")
	_ = writer.WriteField("ownership", "optional")
	part, err := writer.CreateFormFile("file", "sodium.jar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("signed-component-jar-test"))
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	uploaded := invoke("POST", "/api/v1/packages/"+id+"/files", content.Bytes(), writer.FormDataContentType())
	if uploaded.Code != 201 {
		t.Fatalf("upload %d: %s", uploaded.Code, uploaded.Body.String())
	}
	path := "/api/v1/packages/" + id + "/component-catalog"
	state := invoke("GET", path, nil, "")
	if state.Code != 200 || !strings.Contains(state.Body.String(), `"revision":1`) {
		t.Fatalf("load editor: %d %s", state.Code, state.Body.String())
	}
	body := []byte(`{"expectedRevision":1,"catalog":{"schemaVersion":"5.0","revision":1,"digest":"","components":[{"id":"sodium","name":"Sodium","files":["mods/sodium.jar"],"version":"1.0.0","visible":true}],"presets":[{"id":"optimized","name":"Optimized","components":["sodium"]}],"defaultPreset":"optimized"}}`)
	preview := invoke("POST", path+"/preview", body, "application/json")
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"valid":true`) {
		t.Fatalf("preview %d: %s", preview.Code, preview.Body.String())
	}
	saved := invoke("PUT", path, body, "application/json")
	if saved.Code != 200 || !strings.Contains(saved.Body.String(), `"revision":2`) {
		t.Fatalf("save %d: %s", saved.Code, saved.Body.String())
	}
	stale := invoke("PUT", path, body, "application/json")
	if stale.Code != 409 {
		t.Fatalf("stale catalog accepted: %d %s", stale.Code, stale.Body.String())
	}
	invalid := []byte(`{"expectedRevision":2,"catalog":{"schemaVersion":"5.0","components":[{"id":"sodium","name":"Sodium","files":["mods/sodium.jar"],"version":"1.0.0","visible":true,"actions":[{"type":"JvmArgs","args":["-javaagent:evil.jar"]}]}]}}`)
	bad := invoke("POST", path+"/preview", invalid, "application/json")
	if bad.Code != 200 || !strings.Contains(bad.Body.String(), `"valid":false`) {
		t.Fatalf("dangerous action accepted: %d %s", bad.Code, bad.Body.String())
	}
}
