package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
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
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
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
			t.Fatalf("upload %s => %d %s", p, res.Code, res.Body.String())
		}
		if expect == 201 {
			if err := json.Unmarshal(res.Body.Bytes(), &ws); err != nil {
				t.Fatal(err)
			}
		}
	}
	upload("saves/world/level.dat", "secret", ws.Data.Revision, 400) // never a managed path
	upload("mods/client.jar", "jar-test", ws.Data.Revision, 201)
	upload("assets/indexes/demo.json", "{}", ws.Data.Revision, 201)
	upload("mods/stale.jar", "old", 1, 409) // CAS stale write cannot overwrite
	// Delete is a real revision-checked metadata mutation, not a UI-only toggle.
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":1,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 409 {
		t.Fatalf("stale remove: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/missing.jar"}`), "application/json")
	if rr.Code != 404 {
		t.Fatalf("missing remove: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 200 {
		t.Fatalf("remove imported file: %d %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &ws); err != nil {
		t.Fatal(err)
	}
	upload("mods/client.jar", "jar-fixed", ws.Data.Revision, 201)

	rr = call("GET", "/api/v1/build-workspaces/"+id+"/scan", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"status":"passed"`) {
		t.Fatalf("scan %d %s", rr.Code, rr.Body.String())
	}
	rr = call("GET", "/api/v1/build-workspaces/"+id+"/diff", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"change":"added"`) {
		t.Fatalf("diff %d %s", rr.Code, rr.Body.String())
	}
	stage := `{"revision":` + strconv.FormatInt(ws.Data.Revision, 10) + `,"paths":["mods/client.jar","assets/indexes/demo.json"]}`
	rr = call("POST", "/api/v1/build-workspaces/"+id+"/stage", []byte(stage), "application/json")
	if rr.Code != 200 {
		t.Fatalf("stage %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ws)
	rr = call("GET", "/api/v1/build-workspaces/"+id+"/validate", nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"valid":true`) {
		t.Fatalf("validate %d %s", rr.Code, rr.Body.String())
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
		t.Fatal("build digest is not reproducible")
	}
	rr = call("POST", "/api/v1/build-workspaces/"+id+"/build", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`}`), "application/json")
	if rr.Code != 201 {
		t.Fatalf("build %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ws)
	// Source objects cannot be fetched over the public package-file route.
	rr = call("GET", "/api/v1/files/demo-project/"+id+"/objects/"+validation.Data.BuildDigest, nil, "")
	if rr.Code != 404 {
		t.Fatalf("workspace source publicly served: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("DELETE", "/api/v1/build-workspaces/"+id+"/files", []byte(`{"revision":`+strconv.FormatInt(ws.Data.Revision, 10)+`,"path":"mods/client.jar"}`), "application/json")
	if rr.Code != 409 {
		t.Fatalf("built package must be immutable: %d %s", rr.Code, rr.Body.String())
	}
	rr = call("POST", "/api/v1/packages/"+ws.Data.PackageID+"/files", nil, "")
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), "immutable") {
		t.Fatalf("direct upload changed built package: %d %s", rr.Code, rr.Body.String())
	}

	if ws.Data.PackageID == "" || ws.Data.BuildDigest != validation.Data.BuildDigest {
		t.Fatalf("build state %#v", ws.Data)
	}
	rr = call("GET", "/api/v1/packages/"+ws.Data.PackageID, nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "mods/client.jar") || !strings.Contains(rr.Body.String(), `"immutableBuild":true`) {
		t.Fatalf("package %d %s", rr.Code, rr.Body.String())
	}
	rr = call("GET", "/api/v1/build-workspaces/"+id, nil, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"state":"built"`) {
		t.Fatalf("persisted build %d %s", rr.Code, rr.Body.String())
	}
}
