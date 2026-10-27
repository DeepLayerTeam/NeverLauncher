package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

type fakeS3Growth struct {
	mu         sync.Mutex
	data       map[string][]byte
	corrupt    bool
	denyDelete bool
}

func (f *fakeS3Growth) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	if r.Header.Get("X-Amz-Date") == "" {
		http.Error(w, "no timestamp", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/growth-bucket" && r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/growth-bucket/neverlauncher-growth-check/") {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		data, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			http.Error(w, "read", 500)
			return
		}
		hash := sha256.Sum256(data)
		if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(hash[:]) {
			http.Error(w, "hash mismatch", 403)
			return
		}
		f.data[r.URL.Path] = data
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		data, ok := f.data[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.corrupt {
			data = []byte("tampered")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case http.MethodDelete:
		if f.denyDelete {
			http.Error(w, "delete denied", 403)
			return
		}
		delete(f.data, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "invalid method", 405)
	}
}
func TestS3CrossClientProbeAndCleanup03212(t *testing.T) {
	fake := &fakeS3Growth{data: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(fake.serve))
	defer srv.Close()
	cfg := storage.S3Config{Endpoint: srv.URL, Bucket: "growth-bucket", Region: "test-1", AccessKey: "access", SecretKey: "secret", PathStyle: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := verifyS3Growth(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	if len(fake.data) != 0 {
		t.Fatal("S3 temporary probe was not removed")
	}
	fake.corrupt = true
	fake.mu.Unlock()
	if err := verifyS3Growth(ctx, cfg); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corrupt S3 read incorrectly accepted: %v", err)
	}
	fake.mu.Lock()
	if len(fake.data) != 0 {
		t.Fatal("corrupted probe was not removed")
	}
	fake.corrupt = false
	fake.denyDelete = true
	fake.mu.Unlock()
	if err := verifyS3Growth(ctx, cfg); err == nil || !strings.Contains(err.Error(), "remove S3 probe object") {
		t.Fatalf("failed cleanup accepted: %v", err)
	}
}
func TestGrowthFailsClosedOnMissingPostgres03212(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	plan := Plan{Mode: Standard, Storage: "local"}
	result, err := VerifyGrowth(ctx, config.Config{DatabaseDSN: "postgres://127.0.0.1:1/not-running?sslmode=disable"}, plan)
	if err == nil || result.PostgreSQL {
		t.Fatalf("missing PostgreSQL incorrectly accepted: %+v %v", result, err)
	}
}
func TestGrowthLivePostgresRedis03212(t *testing.T) {
	pg := os.Getenv("NEVERLAUNCHER_GROWTH_TEST_PG_DSN")
	redis := os.Getenv("NEVERLAUNCHER_GROWTH_TEST_REDIS_URL")
	if pg == "" || redis == "" {
		t.Skip("live PostgreSQL/Redis URLs required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := verifyPostgresGrowth(ctx, pg); err != nil {
		t.Fatal(err)
	}
	if err := verifyRedisGrowth(ctx, redis); err != nil {
		t.Fatal(err)
	}
}
