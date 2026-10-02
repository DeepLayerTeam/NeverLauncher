package main

import (
	"os"
	"strings"
	"testing"
)

func TestLoaderPayloadCacheRejectsAndQuarantinesCorruptPayload(t *testing.T) {
	root := t.TempDir()
	payload := []byte("12345678")
	sha, err := storeLoaderPayloadCacheBytes(root, "fabric", "26.3", "https://meta.fabricmc.net/test", payload)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, payloadPath, err := loaderPayloadCachePaths(root, sha)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte("87654321"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLoaderPayloadCacheBytes(root, "fabric", "26.3", "https://meta.fabricmc.net/test", sha, maxCompatibilityArtifact); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("corrupt loader cache must fail closed, got %v", err)
	}
	if _, err := os.Stat(payloadPath); !os.IsNotExist(err) {
		t.Fatalf("corrupt cache payload must be quarantined, stat=%v", err)
	}
}
