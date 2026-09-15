package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestCanonicalOperationsBackupFlow(t *testing.T) {
	handler := testServer(t)
	token := loginAdmin(t, handler)
	auth := func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) }

	for _, path := range []string{
		"/api/v1/operations/backup/status",
		"/api/v1/operations/audit/export",
		"/api/v1/operations/diagnostics-bundle",
		"/api/v1/operations/compliance",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		auth(req)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s => %d %s", path, res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/operations/backups", nil)
	auth(req)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), "created") {
		t.Fatalf("backup create => %d %s", res.Code, res.Body.String())
	}
	var created struct {
		BackupID string `json:"backupId"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.BackupID == "" {
		t.Fatalf("backupId missing: %v %s", err, res.Body.String())
	}

	for _, step := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/operations/backups/" + created.BackupID},
		{http.MethodPost, "/api/v1/operations/backups/" + created.BackupID + "/restore-dry-run"},
	} {
		req = httptest.NewRequest(step.method, step.path, nil)
		auth(req)
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), created.BackupID) {
			t.Fatalf("%s %s => %d %s", step.method, step.path, res.Code, res.Body.String())
		}
	}
}

func TestBackupRestoreRestoresStorageObject(t *testing.T) {
	cfg := config.Config{
		PublicURL:          "http://example.test",
		RepositoryDriver:   "memory",
		StorageDriver:      "local",
		StorageLocalPath:   t.TempDir(),
		BackupRoot:         t.TempDir(),
		Environment:        "test",
		AuthTokenSecret:    "test-secret-for-backup-restore",
		AuthTokenTTLHours:  1,
		CORSAllowedOrigins: []string{"http://example.test"},
	}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	store := storage.NewLocalStorage(cfg.StorageLocalPath)
	if _, _, err := store.Save("demo-project", "demo-project-vanilla-3.4.0", "README.txt", strings.NewReader("before-backup")); err != nil {
		t.Fatal(err)
	}
	h := Server{Version: "0.10.0-P3.2v4", Config: cfg, Repo: repo, Storage: store}.Handler()
	token := loginAdmin(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/operations/backups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("create => %d %s", res.Code, res.Body.String())
	}
	var created struct {
		BackupID string `json:"backupId"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil || created.BackupID == "" {
		t.Fatalf("backupId: %v %s", err, res.Body.String())
	}

	if _, _, err := store.Save("demo-project", "demo-project-vanilla-3.4.0", "README.txt", strings.NewReader("after-backup")); err != nil {
		t.Fatal(err)
	}
	body := `{"confirm":"` + created.BackupID + `","database":false,"storage":true}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/operations/backups/"+created.BackupID+"/restore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("restore => %d %s", res.Code, res.Body.String())
	}
	reader, _, err := store.Open("demo-project", "demo-project-vanilla-3.4.0", "README.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "before-backup" {
		t.Fatalf("storage restore mismatch: %q", string(data))
	}
}
