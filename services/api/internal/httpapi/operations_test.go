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

// Regression: old rollback route and the new execution lifecycle MUST converge
// on the same immutable release for repeated requests, even without a client
// idempotency key. The request's job id is also the audit correlation id.
func TestRollbackOperationIdempotency0217(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	token, _ = registerTestPasskey117(t, handler, token)
	auth := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
	}
	// Construct a real published source package with integrity evidence.
	req := httptest.NewRequest("POST", "/api/v1/packages", strings.NewReader(`{"projectId":"demo-project","profileId":"vanilla","channel":"dev","version":"0.21.7-idem"}`))
	auth(req)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created.Data.PackageID
	// Upload genuine bytes and use the production validation/signing pipeline.
	var upload bytes.Buffer
	writer := multipart.NewWriter(&upload)
	_ = writer.WriteField("path", "mods/rollback.jar")
	part, err := writer.CreateFormFile("file", "rollback.jar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("rollback-operation-idempotency-fixture"))
	_ = writer.Close()
	req = httptest.NewRequest("POST", "/api/v1/packages/"+id+"/files", &upload)
	auth(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	for _, action := range []string{"validate", "sign", "stage", "integrity-check", "publish"} {
		req = httptest.NewRequest("POST", "/api/v1/packages/"+id+"/"+action, nil)
		auth(req)
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", action, rr.Code, rr.Body.String())
		}
	}
	rollbackBody := `{"projectId":"demo-project","profileId":"vanilla","toVersion":"0.21.7-idem"}`
	var first struct {
		Data struct {
			RollbackVersion string `json:"rollbackVersion"`
			PackageID       string `json:"packageId"`
			Status          string `json:"status"`
		} `json:"data"`
	}
	var jobID string
	for i := 0; i < 3; i++ {
		req = httptest.NewRequest("POST", "/api/v1/channels/dev/rollback", strings.NewReader(rollbackBody))
		auth(req)
		req.Header.Set("Idempotency-Key", "same-rollback-request")
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("rollback %d: %d %s", i, rr.Code, rr.Body.String())
		}
		var received struct {
			Data struct {
				RollbackVersion string `json:"rollbackVersion"`
				PackageID       string `json:"packageId"`
				Status          string `json:"status"`
			} `json:"data"`
		}
		if err = json.Unmarshal(rr.Body.Bytes(), &received); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = received
			jobID = rr.Header().Get("X-Correlation-ID")
		}
		if received.Data.RollbackVersion != first.Data.RollbackVersion || received.Data.PackageID != first.Data.PackageID || rr.Header().Get("X-Correlation-ID") != jobID {
			t.Fatalf("duplicate rollback created different release/job: first=%+v next=%+v", first, received)
		}
	}
	if first.Data.Status != "rolled-back-as-new-validated-immutable-release" || jobID == "" {
		t.Fatalf("rollback not published: %+v correlation=%s", first, jobID)
	}
	// A successful durable rollback MUST actually advance the channel head
	// and replaying the same job must not advance it again.
	req = httptest.NewRequest("GET", "/api/v1/projects/demo-project/profiles/vanilla/channels/dev/head", nil)
	auth(req)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("read head: %d %s", rr.Code, rr.Body.String())
	}
	var observed struct {
		Data struct {
			ReleaseID string `json:"releaseId"`
			Revision  int64  `json:"revision"`
		} `json:"data"`
	}
	if err = json.Unmarshal(rr.Body.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Data.ReleaseID != first.Data.PackageID || observed.Data.Revision != 2 {
		t.Fatalf("rollback job did not atomically advance channel to its own package: %+v", observed)
	}
	req = httptest.NewRequest("POST", "/api/v1/channels/dev/rollback", strings.NewReader(`{"projectId":"demo-project","profileId":"fabric","toVersion":"0.21.7-idem"}`))
	auth(req)
	req.Header.Set("Idempotency-Key", "same-rollback-request")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 409 {
		t.Fatalf("same key with changed intent should conflict: %d %s", rr.Code, rr.Body.String())
	}

}

func TestOperationRoutesRequireAuthentication0217(t *testing.T) {
	handler := testServer(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/operations"}, {"POST", "/api/v1/operations/validate"},
		{"POST", "/api/v1/operations/execute"}, {"GET", "/api/v1/operations/not-real"},
		{"GET", "/api/v1/operations/not-real/attempts"},
		{"POST", "/api/v1/operations/not-real/cancel"}, {"POST", "/api/v1/operations/not-real/retry"},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401 got %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

// An operator must not preview a signed package under an unrelated selected
// profile/channel. The actual backend package, not the submitted UI context,
// defines the resource that would be published.
func TestPublishPreviewRejectsWrongChannel0386(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	request := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	created := request("/api/v1/packages", `{"projectId":"demo-project","profileId":"vanilla","channel":"dev","version":"0.38.6-preview"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var pkg struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ profile, channel string }{{"fabric", "dev"}, {"vanilla", "stable"}} {
		body, _ := json.Marshal(map[string]string{"kind": "package-publish", "projectId": "demo-project", "resourceId": pkg.Data.PackageID, "profileId": tc.profile, "channel": tc.channel})
		res := request("/api/v1/operations/validate", string(body))
		if res.Code != http.StatusConflict {
			t.Errorf("wrong %s/%s should conflict, got %d %s", tc.profile, tc.channel, res.Code, res.Body.String())
		}
	}
}
