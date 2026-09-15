package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewS3StorageValidatesRequiredConfig(t *testing.T) {
	if _, err := NewS3Storage(S3Config{}); err == nil {
		t.Fatal("NewS3Storage должен отклонять неполную конфигурацию")
	}
	store, err := NewS3Storage(S3Config{Endpoint: "https://s3.example.ru", Bucket: "bucket", AccessKey: "access", SecretKey: "secret", PathStyle: true})
	if err != nil {
		t.Fatalf("NewS3Storage вернул ошибку для полной конфигурации: %v", err)
	}
	if store.Driver() != "s3" {
		t.Fatalf("неожиданный драйвер: %s", store.Driver())
	}
}

func TestS3SaveStreamsAndSignsPayload(t *testing.T) {
	payload := strings.Repeat("neverlauncher-stream-", 8192)
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method=%s", r.Method)
		}
		if r.URL.Path != "/bucket/project/version/libraries/test.jar" {
			t.Errorf("path=%s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		gotBody = string(body)
		sum := sha256.Sum256([]byte(payload))
		if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
			t.Error("payload hash header mismatch")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing SigV4 authorization")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store, err := NewS3Storage(S3Config{Endpoint: server.URL, Bucket: "bucket", Region: "test", AccessKey: "access", SecretKey: "secret", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	key, size, err := store.Save("project", "version", "libraries/test.jar", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if key != "project/version/libraries/test.jar" || size != int64(len(payload)) || gotBody != payload {
		t.Fatalf("unexpected upload result key=%s size=%d body=%d", key, size, len(gotBody))
	}
}
