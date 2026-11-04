package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTextureRealS3Lifecycle02512 talks to an actual S3-compatible service
// (MinIO in CI). The existing httptest cases separately cover ETag races and
// bad replies; this test verifies real SigV4, conditional PUT, retrieval,
// backup, deletion and recovery against a live object store.
func TestTextureRealS3Lifecycle02512(t *testing.T) {
	endpoint := os.Getenv("TEST_TEXTURE_S3_ENDPOINT_02512")
	if endpoint == "" {
		t.Skip("TEST_TEXTURE_S3_ENDPOINT_02512 not configured")
	}
	cfg := S3Config{Endpoint: endpoint, Bucket: os.Getenv("TEST_TEXTURE_S3_BUCKET_02512"), Region: "us-east-1", AccessKey: os.Getenv("TEST_TEXTURE_S3_ACCESS_KEY_02512"), SecretKey: os.Getenv("TEST_TEXTURE_S3_SECRET_KEY_02512"), PathStyle: true}
	store, err := NewS3Storage(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	if err := store.Health(ctx); err != nil {
		t.Fatalf("real S3 health: %v", err)
	}
	content := []byte("real S3 texture compatibility 0.25.12 " + time.Now().UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	// The importer supplies normalized PNG; this storage test independently
	// checks the actual immutable byte store and its multi-step lifecycle.
	for i := 0; i < 2; i++ {
		if _, _, err := PutTextureImmutable0253(ctx, store, digest, content); err != nil {
			t.Fatalf("conditional PUT #%d: %v", i, err)
		}
	}
	obj := textureFixture0253(content)
	if got := VerifyTexture02511(ctx, store, obj); got.Result != "ok" {
		t.Fatalf("real S3 verification: %+v", got)
	}
	backup := filepath.Join(t.TempDir(), "snapshot")
	if err := BackupTextures0253(ctx, store, []TextureBackupObject0253{obj}, backup); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTextureSafely02511(ctx, store, digest); err != nil {
		t.Fatalf("S3 safe delete: %v", err)
	}
	if got := VerifyTexture02511(ctx, store, obj); got.Result != "unavailable" {
		t.Fatalf("deleted blob still present: %+v", got)
	}
	count, err := RestoreTextures0253(ctx, store, backup, []TextureBackupObject0253{obj})
	if err != nil || count != 1 {
		t.Fatalf("real S3 restore: count=%d err=%v", count, err)
	}
	r, _, err := OpenTexture0252(store, digest)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, content) {
		t.Fatalf("restored content mismatch %v %v", readErr, closeErr)
	}
	if err := DeleteTextureSafely02511(ctx, store, digest); err != nil {
		t.Fatal(err)
	}
}
