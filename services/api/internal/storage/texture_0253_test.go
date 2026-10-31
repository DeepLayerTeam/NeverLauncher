package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func textureFixture0253(payload []byte) TextureBackupObject0253 {
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	return TextureBackupObject0253{Digest: digest, ByteSize: int64(len(payload)), Driver: "local", ObjectKey: "texture-blobs/sha256/" + digest[:2] + "/" + digest + ".png"}
}
func TestTextureLocalBackupRestoreGC0253(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewLocalStorage(root)
	payload := []byte("normalized image mock")
	obj := textureFixture0253(payload)
	if _, _, err := PutTextureImmutable0253(ctx, s, obj.Digest, payload); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snapshot")
	if err := BackupTextures0253(ctx, s, []TextureBackupObject0253{obj}, dest); err != nil {
		t.Fatal(err)
	}
	if err := BackupTextures0253(ctx, s, []TextureBackupObject0253{obj}, dest); err == nil {
		t.Fatal("overwrote backup")
	}
	if err := DeleteTexture0253(ctx, s, obj.Digest); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTexture0253(ctx, s, obj.Digest); err != nil {
		t.Fatal("delete must be idempotent", err)
	}
	if _, _, err := OpenTexture0252(s, obj.Digest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected deleted object, %v", err)
	}
	n, err := RestoreTextures0253(ctx, s, dest, []TextureBackupObject0253{obj})
	if err != nil || n != 1 {
		t.Fatalf("restore %d %v", n, err)
	}
	r, _, err := OpenTexture0252(s, obj.Digest)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(recovered, payload) {
		t.Fatal("restore mismatch", err)
	}
	// Tampered snapshots must be rejected before modifying the storage.
	if err := os.WriteFile(filepath.Join(dest, "blobs", obj.Digest+".png"), []byte(strings.Repeat("x", len(payload))), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTextures0253(ctx, s, dest, []TextureBackupObject0253{obj}); err == nil {
		t.Fatal("accepted corrupt backup")
	}
	if err := DeleteTexture0253(ctx, s, obj.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTextures0253(ctx, s, dest, nil); err == nil {
		t.Fatal("accepted unauthorized backup digest")
	}
}
func TestTextureS3ImmutableConditionalAndDelete0253(t *testing.T) {
	ctx := context.Background()
	payload := []byte("content-hash protected png")
	obj := textureFixture0253(payload)
	var mu sync.Mutex
	stored := map[string][]byte{}
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(r.URL.Path, "/bucket/texture-blobs/sha256/") {
			t.Errorf("unexpected key: %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing SigV4")
		}
		switch r.Method {
		case http.MethodPut:
			puts++
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("S3 conditional PUT missing")
			}
			if r.Header.Get("Content-Type") != "image/png" {
				t.Error("incorrect PNG content type")
			}
			if r.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
				t.Error("incorrect immutable cache header")
			}
			if _, ok := stored[r.URL.Path]; ok {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			data, _ := io.ReadAll(r.Body)
			stored[r.URL.Path] = data
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			data, ok := stored[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(data)
		case http.MethodDelete:
			delete(stored, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	s, err := NewS3Storage(S3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "ak", SecretKey: "sk", Region: "test", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		key, n, err := PutTextureImmutable0253(ctx, s, obj.Digest, payload)
		if err != nil || key != obj.ObjectKey || n != obj.ByteSize {
			t.Fatalf("immutable PUT #%d: key=%s size=%d err=%v", i, key, n, err)
		}
	}
	if puts != 2 {
		t.Fatalf("expected PUT + conditional retry, got %d", puts)
	}
	// Object was tampered with between uploads; accept a collision by key only.
	mu.Lock()
	for k := range stored {
		stored[k] = []byte("tampered")
	}
	mu.Unlock()
	if _, _, err := PutTextureImmutable0253(ctx, s, obj.Digest, payload); err == nil {
		t.Fatal("deduplicated corrupt S3 bytes")
	}
	if err := DeleteTexture0253(ctx, s, obj.Digest); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTexture0253(ctx, s, obj.Digest); err != nil {
		t.Fatal("S3 idempotent delete", err)
	}
}
func TestTextureGCRefusesModifiedLocal0253(t *testing.T) {
	s := NewLocalStorage(t.TempDir())
	payload := []byte("correct")
	obj := textureFixture0253(payload)
	if _, _, err := PutTextureImmutable0253(context.Background(), s, obj.Digest, payload); err != nil {
		t.Fatal(err)
	}
	rel, _ := texturePath0252(obj.Digest)
	dest, _, err := s.objectPath(textureProject0252, textureVersion0252, rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTexture0253(context.Background(), s, obj.Digest); err == nil {
		t.Fatal("deleted modified file")
	}
}

func TestTextureRestoreRepairsCorruptLocal0253(t *testing.T) {
	ctx := context.Background()
	store := NewLocalStorage(t.TempDir())
	png := []byte("good backed up object")
	obj := textureFixture0253(png)
	if _, _, err := PutTextureImmutable0253(ctx, store, obj.Digest, png); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "backup")
	if err := BackupTextures0253(ctx, store, []TextureBackupObject0253{obj}, snapshot); err != nil {
		t.Fatal(err)
	}
	rel, _ := texturePath0252(obj.Digest)
	location, _, _ := store.objectPath(textureProject0252, textureVersion0252, rel)
	if err := os.WriteFile(location, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTextures0253(ctx, store, snapshot, []TextureBackupObject0253{obj}); err != nil {
		t.Fatal(err)
	}
	f, _, err := OpenTexture0252(store, obj.Digest)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(restored, png) {
		t.Fatal("corrupt local file not repaired", err)
	}
}

func TestTextureS3BackupRestoreAndConditionalRepair0253(t *testing.T) {
	ctx := context.Background()
	png := []byte("original s3 verified texture")
	obj := textureFixture0253(png)
	var mu sync.Mutex
	stored := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		key := r.URL.Path
		etag := func(v []byte) string { h := sha256.Sum256(v); return `"` + hex.EncodeToString(h[:]) + `"` }
		switch r.Method {
		case http.MethodPut:
			v, exists := stored[key]
			if r.Header.Get("If-None-Match") == "*" && exists {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if match := r.Header.Get("If-Match"); match != "" && (!exists || match != etag(v)) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			bytes, _ := io.ReadAll(r.Body)
			stored[key] = bytes
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			v, exists := stored[key]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("ETag", etag(v))
			w.Write(v)
		case http.MethodDelete:
			delete(stored, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	store, err := NewS3Storage(S3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "ak", SecretKey: "sk", Region: "test", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	obj.Driver = "s3"
	if _, _, err = PutTextureImmutable0253(ctx, store, obj.Digest, png); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "s3-backup")
	if err = BackupTextures0253(ctx, store, []TextureBackupObject0253{obj}, snapshot); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	for key := range stored {
		stored[key] = []byte("corrupted")
	}
	mu.Unlock()
	n, err := RestoreTextures0253(ctx, store, snapshot, []TextureBackupObject0253{obj})
	if err != nil || n != 1 {
		t.Fatalf("S3 conditional repair %d: %v", n, err)
	}
	f, _, err := OpenTexture0252(store, obj.Digest)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(recovered, png) {
		t.Fatalf("S3 restore mismatch: %v", err)
	}
}
