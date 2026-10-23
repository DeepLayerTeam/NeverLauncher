package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestVerifyTextureLifecycleLocal02511(t *testing.T) {
	ctx := context.Background()
	store := NewLocalStorage(t.TempDir())
	data := []byte("verified local backup test")
	obj := textureFixture0253(data)
	if _, _, err := PutTextureImmutable0253(ctx, store, obj.Digest, data); err != nil {
		t.Fatal(err)
	}
	if got := VerifyTexture02511(ctx, store, obj); got.Result != "ok" {
		t.Fatalf("healthy texture: %+v", got)
	}
	rel, _ := texturePath0252(obj.Digest)
	path, _, _ := store.objectPath(textureProject0252, textureVersion0252, rel)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyTexture02511(ctx, store, obj); got.Result != "corrupt" {
		t.Fatalf("corruption undetected: %+v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := VerifyTexture02511(ctx, store, obj); got.Result != "unavailable" {
		t.Fatalf("missing object undetected: %+v", got)
	}
	if got := VerifyTexture02511(ctx, store, TextureBackupObject0253{Digest: "invalid"}); got.Result != "corrupt" {
		t.Fatalf("bad digest accepted: %+v", got)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if got := VerifyTexture02511(cancelCtx, store, obj); got.Result != "cancelled" {
		t.Fatalf("cancellation ignored: %+v", got)
	}
}

func TestTextureS3GCConditionalDelete02511(t *testing.T) {
	ctx := context.Background()
	data := []byte("immutable texture whose ETag must match")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	var mu sync.Mutex
	object := append([]byte(nil), data...)
	deletes := 0
	mutateDuringDelete := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(r.URL.Path, "/texture-blobs/sha256/") {
			t.Errorf("invalid URL: %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("unsigned S3 request")
		}
		etag := func(p []byte) string { h := sha256.Sum256(p); return `"` + hex.EncodeToString(h[:]) + `"` }
		switch r.Method {
		case http.MethodGet:
			if object == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("ETag", etag(object))
			_, _ = w.Write(object)
		case http.MethodDelete:
			deletes++
			if r.Header.Get("If-Match") == "" {
				t.Error("missing signed conditional delete header")
			}
			if mutateDuringDelete {
				object = []byte("concurrent overwrite")
			}
			if object == nil || r.Header.Get("If-Match") != etag(object) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			object = nil
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	s, err := NewS3Storage(S3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "key", SecretKey: "secret", Region: "eu", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	mutateDuringDelete = true
	if err := DeleteTextureSafely02511(ctx, s, digest); err == nil {
		t.Fatal("lost S3 ETag race was accepted")
	}
	mu.Lock()
	if !bytes.Equal(object, []byte("concurrent overwrite")) {
		t.Error("modified object deleted")
	}
	object = append([]byte(nil), data...)
	mutateDuringDelete = false
	mu.Unlock()
	if err := DeleteTextureSafely02511(ctx, s, digest); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTextureSafely02511(ctx, s, digest); err != nil {
		t.Fatal("missing objects should be idempotent", err)
	}
	mu.Lock()
	if deletes != 2 {
		t.Errorf("unexpected delete count %d", deletes)
	}
	object = []byte("tampered")
	mu.Unlock()
	if err := DeleteTextureSafely02511(ctx, s, digest); err == nil {
		t.Fatal("deleted corrupted S3 bytes")
	}
	mu.Lock()
	if deletes != 2 {
		t.Error("sent DELETE for corrupted S3")
	}
	mu.Unlock()
}

func TestAtomicRepairLeavesNoWindowWithoutObject02511(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := NewLocalStorage(root)
	payload := []byte("correct replacement")
	obj := textureFixture0253(payload)
	if _, _, err := PutTextureImmutable0253(ctx, store, obj.Digest, payload); err != nil {
		t.Fatal(err)
	}
	rel, _ := texturePath0252(obj.Digest)
	path, _, _ := store.objectPath(textureProject0252, textureVersion0252, rel)
	if err := os.WriteFile(path, []byte("old corrupted image"), 0644); err != nil {
		t.Fatal(err)
	}
	openHandle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer openHandle.Close()
	if _, _, err := RestoreTextureObject0253(ctx, store, obj.Digest, payload); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("replacement not published: %v", err)
	}
	old, err := io.ReadAll(openHandle)
	if err != nil || !bytes.Equal(old, []byte("old corrupted image")) {
		t.Fatal("open readers were disrupted")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".texture-repair-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files left over: %v %v", matches, err)
	}
}
