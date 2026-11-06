package prestarter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

// Тест использует настоящий TLS-сервер и принудительно закрывает TCP после частичной доставки.
// Второй запрос должен продолжить получение точно тех же подписанных байтов.
func TestTLSDownloadInterruptedResumeExactSHA0527(t *testing.T) {
	content := []byte("signed-updater-payload-with-enough-bytes-to-resume")
	hash := sha256.Sum256(content)
	var attempts atomic.Int32
	var resumed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq := attempts.Add(1)
		w.Header().Set("ETag", "\"release-etag-0527\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		if seq == 1 {
			if r.Header.Get("Range") != "" {
				t.Errorf("first request used Range")
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(content)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content[:12])
			w.(http.Flusher).Flush()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if r.Header.Get("Range") != "bytes=12-" || r.Header.Get("If-Range") != "\"release-etag-0527\"" {
			t.Errorf("unexpected resume headers: %+v", r.Header)
		}
		resumed.Store(true)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 12-%d/%d", len(content)-1, len(content)))
		w.Header().Set("Content-Length", strconv.Itoa(len(content)-12))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[12:])
	}))
	defer server.Close()
	art := Artifact{URL: server.URL + "/signed-object", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
	root := t.TempDir()
	part := filepath.Join(root, "object.part")
	meta := filepath.Join(root, "object.etag")
	storage := &storage{root: root, http: server.Client()}
	if err := storage.fetch(context.Background(), art, part, meta); err == nil {
		t.Fatal("broken TCP delivery returned success")
	}
	received, err := os.ReadFile(part)
	if err != nil || string(received) != string(content[:12]) {
		t.Fatalf("partial data not persisted for resume: %q %v", received, err)
	}
	if err := storage.fetch(context.Background(), art, part, meta); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 || !resumed.Load() || !hashFile(part, art) {
		t.Fatalf("Не удалось возобновить подписанную загрузку по диапазону: попыток=%d, возобновлено=%v", attempts.Load(), resumed.Load())
	}
}

func TestTLSResumeRejectsWrongServerValidator0527(t *testing.T) {
	content := []byte("immutable-release-payload-with-network-resume")
	hash := sha256.Sum256(content)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("ETag", "\"unexpected-new-version\"")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 8-%d/%d", len(content)-1, len(content)))
		w.Header().Set("Content-Length", strconv.Itoa(len(content)-8))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[8:])
	}))
	defer server.Close()
	art := Artifact{URL: server.URL + "/signed-object", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
	root := t.TempDir()
	part := filepath.Join(root, "part")
	meta := filepath.Join(root, "etag")
	if err := os.WriteFile(part, content[:8], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, []byte("\"old-validator\""), 0600); err != nil {
		t.Fatal(err)
	}
	s := &storage{root: root, http: server.Client()}
	if err := s.fetch(context.Background(), art, part, meta); err == nil {
		t.Fatal("mismatching ETag accepted")
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Fatalf("После несовпадения валидатора остался небезопасный частичный файл: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("Ожидалась одна сетевая попытка, получено %d", calls.Load())
	}
}
