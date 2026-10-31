package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Read-only reconciliation after a lost response must return the original
// durable record, never create a new job or reveal one outside its project.
func TestRecoverOriginalOperation0388(t *testing.T) {
	cfg := config.Config{HTTPAddr: "127.0.0.1:0", PublicURL: "http://example.test", RepositoryDriver: "memory", StorageDriver: "local", StorageLocalPath: t.TempDir(), BackupRoot: t.TempDir(), Environment: "test", AuthTokenSecret: "test-secret-for-integration", AuthTokenTTLHours: 1, WebAuthnRPID: "example.test", WebAuthnRPName: "Launcher Test", WebAuthnOrigins: []string{"http://example.test"}}
	repo := repository.NewMemoryRepository(cfg.PublicURL)
	handler := Server{Version: "0.38.8-test", Config: cfg, Repo: repo, Storage: storage.NewLocalStorage(cfg.StorageLocalPath)}.Handler()
	token := loginAdmin(t, handler)
	input := model.DurableJob{Kind: "package-publish", ActorType: "user", ActorID: "admin", Action: "release:publish", ProjectID: "demo-project", ResourceType: "package", ResourceID: "pkg-recover", IdempotencyKey: "recovery-lost-ack-0388", Payload: []byte(`{"packageId":"pkg-recover"}`), MaxAttempts: 8}
	saved, reused, err := repo.EnqueueDurableJob(context.Background(), input, time.Hour)
	if err != nil || reused || saved.ID == "" {
		t.Fatalf("enqueue: %+v reused=%v err=%v", saved, reused, err)
	}
	lookup := func(path, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	path := "/api/v1/operations/recover?projectId=demo-project&kind=package-publish&idempotencyKey=recovery-lost-ack-0388"
	if r := lookup(path, ""); r.Code != 401 {
		t.Fatalf("anonymous read: %d %s", r.Code, r.Body.String())
	}
	for _, bad := range []string{
		"/api/v1/operations/recover?projectId=other-project&kind=package-publish&idempotencyKey=recovery-lost-ack-0388",
		"/api/v1/operations/recover?projectId=demo-project&kind=channel-rollback&idempotencyKey=recovery-lost-ack-0388",
		"/api/v1/operations/recover?projectId=demo-project&kind=package-publish&idempotencyKey=missing-record-0388",
	} {
		if r := lookup(bad, token); r.Code != 404 {
			t.Fatalf("cross-scope read: %d %s", r.Code, r.Body.String())
		}
	}
	for i := 0; i < 2; i++ {
		r := lookup(path, token)
		if r.Code != 200 || r.Header().Get("X-Correlation-ID") != saved.ID {
			t.Fatalf("recovery %d: %d %s", i, r.Code, r.Body.String())
		}
	}
	original, err := repo.FindOperationByKey(context.Background(), input.Kind, input.ActorID, input.IdempotencyKey)
	if err != nil || original.ID != saved.ID {
		t.Fatalf("journal mutated: %+v %v", original, err)
	}
}
