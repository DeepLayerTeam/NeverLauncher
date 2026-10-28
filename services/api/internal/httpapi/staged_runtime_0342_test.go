package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestStagedExecutionGrantsExactDownloadedBytes0342(t *testing.T) {
	cfg := config.Config{PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), CORSAllowedOrigins: []string{"http://example.test"}, Environment: "test", AuthTokenSecret: "staged-0342-test-secret-with-enough-entropy", AuthTokenTTLHours: 1, WebAuthnRPID: "example.test", WebAuthnRPName: "NeverLauncher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	store := storage.NewLocalStorage(cfg.StorageLocalPath)
	h := Server{Version: "0.34.2", Config: cfg, Repo: repo, Storage: store}.Handler()
	admin := loginAdmin(t, h)
	admin, _ = registerTestPasskey117(t, h, admin)
	id, _ := createStagedIntegrityPackageInChannel0341(t, h, admin, "0.34.2-immutable", "dev")
	call := func(method, path, auth string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	// Previous public delivery leaked staged files without any grant.
	pub := call("GET", "/api/v1/files/demo-project/"+id+"/mods/honest-validation.jar", "", nil)
	if pub.Code != 404 {
		t.Fatalf("staged file is public: %d %s", pub.Code, pub.Body.String())
	}
	grantResp := call("POST", "/api/v1/packages/"+id+"/staged-runs", admin, []byte(`{}`))
	if grantResp.Code != 201 {
		t.Fatalf("issue grant: %d %s", grantResp.Code, grantResp.Body.String())
	}
	var issued struct {
		Data struct {
			Token          string `json:"token"`
			RunID          string `json:"runId"`
			ManifestSHA256 string `json:"manifestSha256"`
			ArtifactSHA256 string `json:"artifactSha256"`
		} `json:"data"`
	}
	if e := json.Unmarshal(grantResp.Body.Bytes(), &issued); e != nil {
		t.Fatal(e)
	}
	if issued.Data.Token == "" || issued.Data.RunID == "" {
		t.Fatal("empty staging grant")
	}
	snapshot := call("GET", "/api/v1/staged-runs/"+id+"/snapshot", issued.Data.Token, nil)
	if snapshot.Code != 200 || !strings.Contains(snapshot.Body.String(), "signedManifest") {
		t.Fatalf("snapshot: %d %s", snapshot.Code, snapshot.Body.String())
	}
	path := "/api/v1/staged-runs/" + id + "/files/mods/honest-validation.jar"
	if rr := call("GET", path, "", nil); rr.Code != 401 {
		t.Fatalf("unguarded file: %d", rr.Code)
	}
	if rr := call("GET", path, issued.Data.Token+"x", nil); rr.Code != 401 {
		t.Fatalf("forged grant: %d", rr.Code)
	}
	rr := call("GET", path, issued.Data.Token, nil)
	if rr.Code != 200 || rr.Body.String() != "neverlauncher-0.21.2-runtime-validation" {
		t.Fatalf("real downloaded bytes incorrect: %d %q", rr.Code, rr.Body.String())
	}
	g, err := (&Server{Config: cfg}).parseGrant0342(issued.Data.Token)
	if err != nil {
		t.Fatal(err)
	}
	g.PackageID = "different-package"
	forged, _ := (&Server{Config: cfg}).issueGrant0342(g)
	if rr := call("GET", path, forged, nil); rr.Code != 401 {
		t.Fatalf("cross-package grant: %d", rr.Code)
	}
	// Append a verified manifest-level report. This does NOT open stable.
	now := time.Now().UTC()
	report := stagedRunReport0342{Schema: stagedRunSchema0342, RunID: issued.Data.RunID, PackageID: id, ManifestSHA256: issued.Data.ManifestSHA256, ArtifactSHA256: issued.Data.ArtifactSHA256, StartedAt: now.Add(-time.Second), FinishedAt: now, Stages: map[string]stagedStep0342{"manifest-files": {Status: "passed", Detail: "observed download"}, "materialization": {Status: "failed", Detail: "missing runtime lock"}}}
	body, _ := json.Marshal(report)
	if rr := call("POST", "/api/v1/staged-runs/"+id+"/results", issued.Data.Token, body); rr.Code != 201 {
		t.Fatalf("report: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call("POST", "/api/v1/staged-runs/"+id+"/results", issued.Data.Token, body); rr.Code != 409 {
		t.Fatalf("report replay accepted: %d", rr.Code)
	}
	list := call("GET", "/api/v1/packages/"+id+"/staged-runs", admin, nil)
	if list.Code != 200 || !strings.Contains(list.Body.String(), issued.Data.RunID) || !strings.Contains(list.Body.String(), `"trustedCertification":false`) {
		t.Fatalf("report not persisted: %d %s", list.Code, list.Body.String())
	}
	// Object mutation after token issue MUST be detected before emitting HTTP 200.
	_, _, e := store.Save("demo-project", id, "mods/honest-validation.jar", strings.NewReader("poison bytes with owner-recomputed hashes not in snapshot"))
	if e != nil {
		t.Fatal(e)
	}
	if rr := call("GET", path, issued.Data.Token, nil); rr.Code != 409 {
		t.Fatalf("corrupt stored object served as certified: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStagedGrantRejectsStaleAndCrossSnapshot0342(t *testing.T) {
	s := Server{Config: config.Config{AuthTokenSecret: "staged-0342-test-secret-with-enough-entropy"}}
	g := stagedGrant0342{Schema: stagedGrantSchema0342, PackageID: "package", ProjectID: "project", ManifestSHA256: strings.Repeat("a", 64), ArtifactSHA256: strings.Repeat("b", 64), RunID: "run-id", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	token, err := s.issueGrant0342(g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.parseGrant0342(token); err == nil {
		t.Fatal("expired grant accepted")
	}
	g.ExpiresAt = time.Now().Add(20 * time.Minute).Unix()
	token, _ = s.issueGrant0342(g)
	if _, err = s.parseGrant0342(token); err != nil {
		t.Fatal(err)
	}
	other := Server{Config: config.Config{AuthTokenSecret: "other-0342-test-secret-with-enough-entropy"}}
	if _, err = other.parseGrant0342(token); err == nil {
		t.Fatal("other server secret accepted")
	}
}
