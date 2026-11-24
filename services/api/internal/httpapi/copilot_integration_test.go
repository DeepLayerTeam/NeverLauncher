package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/aigateway"
	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// No paid provider traffic: exercise real session, signature, release validation,
// durable repository and operation routes; the gateway is used only for RBAC.
func TestCopilotConfirmedOperation124(t *testing.T) {
	cfg := config.Config{HTTPAddr: "127.0.0.1:0", PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-for-integration", AuthTokenTTLHours: 1, WebAuthnRPID: "example.test", WebAuthnRPName: "Launcher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	ai := aigateway.New(aigateway.Config{Roles: map[string]bool{"owner": true}, MaxConcurrent: 1}, nil)
	h := Server{Version: "1.2.4", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath), AI: ai}.Handler()
	token := loginAdmin(t, h)
	token, _ = registerTestPasskey117(t, h, token)
	call := func(path, body string) *httptest.ResponseRecorder {
		return request0211(t, h, http.MethodPost, path, token, body)
	}
	created := call("/api/v1/packages", `{"projectId":"demo-project","profileId":"vanilla","channel":"dev","version":"1.2.4-copilot-test"}`)
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var pkg struct {
		Data struct {
			PackageID string `json:"packageId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &pkg); err != nil || pkg.Data.PackageID == "" {
		t.Fatal("missing package", err)
	}
	id := pkg.Data.PackageID
	configurePackageRuntimeTest(t, h, token, id)
	var upload bytes.Buffer
	mw := multipart.NewWriter(&upload)
	_ = mw.WriteField("path", "mods/copilot.jar")
	part, err := mw.CreateFormFile("file", "copilot.jar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("copilot-fixture"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/"+id+"/files", &upload)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("upload %d %s", rr.Code, rr.Body.String())
	}
	for _, action := range []string{"validate", "sign", "stage", "integrity-check", "publish"} {
		res := call("/api/v1/packages/"+id+"/"+action, "")
		if res.Code != 200 {
			t.Fatalf("%s %d %s", action, res.Code, res.Body.String())
		}
	}
	intent := operationRequest0217{Kind: durableRollbackKind0217, ProjectID: "demo-project", ProfileID: "vanilla", Channel: "dev", ToVersion: "1.2.4-copilot-test", IdempotencyKey: "copilot:12345678-abcd-4000-8000-123456789abc"}
	body := func(x operationRequest0217) string {
		b, e := json.Marshal(x)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	if r := call("/api/v1/operations/execute", body(intent)); r.Code != 403 {
		t.Fatalf("unconfirmed %d %s", r.Code, r.Body.String())
	}
	r := call("/api/v1/operations/validate", body(intent))
	if r.Code != 200 {
		t.Fatalf("preview %d %s", r.Code, r.Body.String())
	}
	var preview struct {
		Data struct {
			Ticket string `json:"copilotConfirmation"`
		} `json:"data"`
	}
	if e := json.Unmarshal(r.Body.Bytes(), &preview); e != nil || preview.Data.Ticket == "" {
		t.Fatal("missing ticket", e)
	}
	intent.CopilotConfirmation = preview.Data.Ticket
	changed := intent
	changed.CopilotConfirmation += "x"
	if r = call("/api/v1/operations/execute", body(changed)); r.Code != 409 {
		t.Fatalf("tamper %d %s", r.Code, r.Body.String())
	}
	changed = intent
	changed.IdempotencyKey = "copilot:12345678-abcd-4000-8000-123456789abd"
	if r = call("/api/v1/operations/execute", body(changed)); r.Code != 409 {
		t.Fatalf("changed key %d %s", r.Code, r.Body.String())
	}
	// An allowed owner must still pass fresh MFA; the same verified request creates only one job.
	r = call("/api/v1/operations/execute", body(intent))
	if r.Code != 202 {
		t.Fatalf("execute %d %s", r.Code, r.Body.String())
	}
	jobID := r.Header().Get("X-Correlation-ID")
	if jobID == "" {
		t.Fatal("missing job")
	}
	r = call("/api/v1/operations/execute", body(intent))
	if r.Code != 202 || r.Header().Get("X-Correlation-ID") != jobID {
		t.Fatalf("replay %d %s", r.Code, r.Body.String())
	}
	r = request0211(t, h, http.MethodGet, "/api/v1/operations/recover?projectId=demo-project&kind=channel-rollback&idempotencyKey="+intent.IdempotencyKey, token, "")
	if r.Code != 200 || r.Header().Get("X-Correlation-ID") != jobID {
		t.Fatalf("recover %d %s", r.Code, r.Body.String())
	}
	count := 0
	for _, e := range repo.ListAuditEvents() {
		if e.Action == "copilot:confirmed:channel-rollback" && e.Target == jobID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("audit count %d", count)
	}
	// Unknown kind cannot become executable just because it uses the copilot prefix.
	bad := strings.Replace(body(intent), "channel-rollback", "shell", 1)
	if r = call("/api/v1/operations/execute", bad); r.Code != 400 {
		t.Fatalf("unknown kind %d", r.Code)
	}
}
