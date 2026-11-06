package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Сквозное HTTP-преобразование должно пройти авторизацию, предпросмотр и атомарное
// сохранение. Оно не должно создавать профиль при заблокированном вводе или
// устаревшем хеше.
func TestGAHTTPGravitPreviewCommitAndConflict0230(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	route := "/api/v1/admin/projects/demo-project/profiles/"
	call := func(action string, input []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, route+action, bytes.NewReader(input))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	source := json.RawMessage(`{"title":"GA Vanilla","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"classLoaderConfig":"SYSTEM_ARGS"}`)
	request := func(hash string, raw json.RawMessage) []byte {
		b, err := json.Marshal(map[string]any{
			"id": "ga-imported-0230", "name": "GA imported", "loaderHint": "vanilla",
			"source": raw, "sourceSha256": hash, "version": "ga-0230", "channel": "dev",
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	preview := call("inspect-gravit", request("", source))
	if preview.Code != 200 {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	var report struct {
		Data struct {
			Ready bool   `json:"ready"`
			SHA   string `json:"sourceSha256"`
		} `json:"data"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Data.Ready || len(report.Data.SHA) != 64 {
		t.Fatalf("Предварительный просмотр не готов: %s", preview.Body.String())
	}
	if result := call("import-gravit", request("stale", source)); result.Code != 409 {
		t.Fatalf("Принят устаревший источник: %d %s", result.Code, result.Body.String())
	}
	blocked := json.RawMessage(`{"title":"Blocked","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"classLoaderConfig":"BRIDGE"}`)
	if result := call("import-gravit", request(report.Data.SHA, blocked)); result.Code != 422 {
		t.Fatalf("Заблокированное действие ошибочно разрешено: %d %s", result.Code, result.Body.String())
	}
	imported := call("import-gravit", request(report.Data.SHA, source))
	if imported.Code != 201 {
		t.Fatalf("commit: %d %s", imported.Code, imported.Body.String())
	}
	var saved struct {
		Data struct {
			Profile struct {
				Revision int64  `json:"revision"`
				Digest   string `json:"digest"`
			} `json:"profile"`
			Workspace struct {
				Revision      int64  `json:"revision"`
				ProfileDigest string `json:"profileDigest"`
				State         string `json:"state"`
			} `json:"workspace"`
		} `json:"data"`
	}
	if err := json.Unmarshal(imported.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Data.Profile.Revision != 1 || saved.Data.Workspace.Revision != 1 || saved.Data.Workspace.ProfileDigest != saved.Data.Profile.Digest || saved.Data.Workspace.State != "importing" {
		t.Fatalf("Рабочее пространство не закреплено: %s", imported.Body.String())
	}
	if result := call("import-gravit", request(report.Data.SHA, source)); result.Code != 409 {
		t.Fatalf("Повторный импорт ошибочно принят: %d %s", result.Code, result.Body.String())
	}
}
