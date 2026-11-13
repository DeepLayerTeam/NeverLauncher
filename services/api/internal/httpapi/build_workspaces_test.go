package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBuildWorkspaceDirectoryStageAndMaterialize0226(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	call := func(method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	create := `{"projectId":"demo-project","profileId":"vanilla","channel":"stable","version":"0.22.6-e2e","settings":{"minecraft":{"version":"1.21.1","loader":"vanilla"},"runtime":{"java":{"majorVersion":17,"distribution":"any"},"memory":{"minimumMb":512,"recommendedMb":2048,"maximumMb":8192}}}}`
	rr := call("POST", "/api/v1/build-workspaces", []byte(create), "application/json")
	if rr.Code != 201 {
		t.Fatalf("создание: %d %s", rr.Code, rr.Body.String())
	}
	var ws struct {
		Data struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Files    []struct {
				Path string `json:"path"`
			} `json:"files"`
			PackageID   string `json:"packageId"`
			BuildDigest string `json:"buildDigest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &ws); err != nil {
		t.Fatal(err)
	}
	id := ws.Data.ID
	upload := func(p, contents string, rev int64, expect int) {
		var buf bytes.Buffer
		multi := multipart.NewWriter(&buf)
		_ = multi.WriteField("path", p)
		_ = multi.WriteField("revision", strconv.FormatInt(rev, 10))
		_ = multi.WriteField("ownership", "required")
		f, _ := multi.CreateFormFile("file", p)
		_, _ = f.Write([]byte(contents))
		_ = multi.Close()
		res := call("POST", "/api/v1/build-workspaces/"+id+"/files", buf.Bytes(), multi.FormDataContentType())
		if res.Code != expect {
			t.Fatalf("загрузка %s => %d %s", p, res.Code, res.Body.String())
		}
		if expect == 201 {
			if err := json.Unmarshal(res.Body.Bytes(), &ws); err != nil {
				t.Fatal(err)
			}
		}
	}
	upload("saves/world/level.dat", "secret", ws.Data.Revision, 400) // Никогда не использовать как управляемый путь.
	upload("mods/client.jar", "jar-test", ws.Data.Revision, 201)
	upload("assets/indexes/demo.json", "{}", ws.Data.Revision, 201)
	upload("mods/stale.jar", "old", 1, 409) // устаревшая запись CAS не может перезаписать данные
	// Удаление действительно изменяет метаданные с проверкой ревизии, а не просто
	// переключает флаг интерфейса.
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":1,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 409 {
		t.Fatalf("удаление с устаревшей ревизией: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/missing.jar"}`), "application/json")
	if rr.Code != 404 {
		t.Fatalf("удаление отсутствующего объекта: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 200 {
		t.Fatalf("удаление импортированного файла: %d %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &ws); err != nil {
		t.Fatal(err)
	}
	upload("mods/client.jar", "jar-fixed", ws.Data.Revision, 201)

	rr = call("GET", "/api/v1/build-workspaces/"+id+"/scan", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"status":"passed"`) {
		t.Fatalf("сканирование: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("GET", "/api/v1/build-workspaces/"+id+"/diff", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"change":"added"`) {
		t.Fatalf("сравнение: %d %s", rr.Code, rr.Body.String())
	}
	stage := `{"revision":` + strconv.FormatInt(ws.Data.Revision, 10) + `,"paths":["mods/client.jar","assets/indexes/demo.json"]}`
	rr = call("POST", "/api/v1/build-workspaces/"+id+"/stage", []byte(stage), "application/json")
	if rr.Code != 200 {
		t.Fatalf("подготовка: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ws)
	rr = call("GET", "/api/v1/build-workspaces/"+id+"/validate", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"valid":true`) {
		t.Fatalf("проверка: %d %s", rr.Code, rr.Body.String())
	}
	var validation struct {
		Data struct {
			BuildDigest string `json:"buildDigest"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &validation)
	rr = call("GET", "/api/v1/build-workspaces/"+id+"/validate", nil, "")
	var repeated struct {
		Data struct {
			BuildDigest string `json:"buildDigest"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &repeated)
	if validation.Data.BuildDigest == "" || repeated.Data.BuildDigest != validation.Data.BuildDigest {
		t.Fatal("хеш сборки невозможно воспроизвести")
	}
	rr = call("POST", "/api/v1/build-workspaces/"+id+"/build", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`}`), "application/json")
	if rr.Code != 201 {
		t.Fatalf("сборка: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ws)
	// Исходные объекты нельзя получить через публичный маршрут файлов пакета.
	rr = call("GET", "/api/v1/files/demo-project/"+id+"/objects/"+validation.Data.BuildDigest, nil, "")
	if rr.Code != 404 {
		t.Fatalf("исходные файлы рабочего пространства доступны публично: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 409 {
		t.Fatalf("собранный пакет должен быть неизменяемым: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("POST", "/api/v1/packages/"+ws.Data.PackageID+"/files", nil, "")
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), "immutable") {
		t.Fatalf("прямая загрузка изменила собранный пакет: %d %s", rr.Code, rr.Body.String())
	}

	if ws.Data.PackageID == "" || ws.Data.BuildDigest != validation.Data.BuildDigest {
		t.Fatalf("состояние сборки: %#v", ws.Data)
	}
	rr = call("GET", "/api/v1/packages/"+ws.Data.PackageID, nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "mods/client.jar") || !strings.Contains(rr.Body.String(), `"immutableBuild":true`) {
		t.Fatalf("пакет: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("GET", "/api/v1/build-workspaces/"+id, nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"state":"built"`) {
		t.Fatalf("сохранённая сборка: %d %s", rr.Code, rr.Body.String())
	}
}
