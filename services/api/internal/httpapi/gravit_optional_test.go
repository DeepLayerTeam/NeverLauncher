package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGravitOptionalPreviewSaveLifecycle02411(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	request := func(method, path string, body []byte, ctype string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	created := request("POST", "/api/v1/packages", []byte(`{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.24.11-gravit-test","manifestSchemaVersion":"3.0"}`), "application/json")
	if created.Code != 201 {
		t.Fatalf("package: %d %s", created.Code, created.Body.String())
	}
	var payload struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if e := json.Unmarshal(created.Body.Bytes(), &payload); e != nil {
		t.Fatal(e)
	}
	id := payload.Data.PackageID
	path := "/api/v1/packages/" + id + "/component-catalog"
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("path", "mods/nei.jar")
	_ = writer.WriteField("ownership", "optional")
	part, _ := writer.CreateFormFile("file", "nei.jar")
	_, _ = part.Write([]byte("gravit-migration-hashed-optional"))
	_ = writer.Close()
	uploaded := request("POST", "/api/v1/packages/"+id+"/files", buf.Bytes(), writer.FormDataContentType())
	if uploaded.Code != 201 {
		t.Fatalf("upload %d %s", uploaded.Code, uploaded.Body.String())
	}
	source := `{"updateOptional":[{"name":"NEI","mark":true,"actions":[{"type":"file","files":{"mods/nei.jar":""}}]}]}`
	makeReq := func(rev int, src string) []byte {
		b, _ := json.Marshal(map[string]any{"expectedRevision": rev, "source": src})
		return b
	}
	preview := request("POST", path+"/gravit-preview", makeReq(1, source), "application/json")
	if preview.Code != 200 {
		t.Fatalf("preview %d %s", preview.Code, preview.Body.String())
	}
	var result struct {
		Data struct {
			CanApply  bool `json:"canApply"`
			Migration struct {
				Catalog      json.RawMessage `json:"catalog"`
				SourceSHA256 string          `json:"sourceSha256"`
			} `json:"migration"`
		} `json:"data"`
	}
	if e := json.Unmarshal(preview.Body.Bytes(), &result); e != nil || !result.Data.CanApply || len(result.Data.Migration.SourceSHA256) != 64 {
		t.Fatalf("preview invalid %v %s", e, preview.Body.String())
	}
	commit, _ := json.Marshal(map[string]any{"expectedRevision": 1, "catalog": result.Data.Migration.Catalog})
	saved := request("PUT", path, commit, "application/json")
	if saved.Code != 200 || !strings.Contains(saved.Body.String(), `"revision":2`) {
		t.Fatalf("save %d %s", saved.Code, saved.Body.String())
	}
	stale := request("POST", path+"/gravit-preview", makeReq(1, source), "application/json")
	if stale.Code != 409 {
		t.Fatalf("stale accepted %d", stale.Code)
	}
	blocked := request("POST", path+"/gravit-preview", makeReq(2, `{"updateOptional":[{"name":"Bad","actions":[{"type":"file","files":{"mods/nei.jar":"mods/evil.jar"}}]}]}`), "application/json")
	if blocked.Code != 200 || !strings.Contains(blocked.Body.String(), `"canApply":false`) {
		t.Fatalf("invalid conversion accepted %d %s", blocked.Code, blocked.Body.String())
	}
}
