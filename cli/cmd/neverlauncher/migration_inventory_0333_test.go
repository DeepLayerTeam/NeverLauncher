package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGravitSourceExportCLI0333(t *testing.T) {
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	// A manifest with the actual canonical JSON layout is attached to the export.
	manifest := `{"format":"neverlauncher.gravit-source-inventory.v1","sourceSha256":"aabb","sourceBytes":2,"sourceEntries":1,"totalBytes":6,"sensitiveEntries":0,"categories":{"asset":1},"authProviders":{},"textureProviders":{},"optionalActions":{},"serverReferences":0,"files":[{"path":"assets/x","kind":"asset","size":6,"sha256":"` + sha0333([]byte("source")) + `"}],"manifestSha256":""}`
	h := sha256.Sum256([]byte(manifest))
	expected := hex.EncodeToString(h[:])
	f, e := zipWriter.Create(".never-migration/inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte(manifest + "\n"))
	f, e = zipWriter.Create("assets/x")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte("source"))
	if e = zipWriter.Close(); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/export" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/zip" {
			t.Errorf("bad upload headers: %+v", r.Header)
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("X-Migration-Manifest-SHA256", expected)
		_, _ = w.Write(archive.Bytes())
	}))
	defer server.Close()
	dir := t.TempDir()
	sourceFile := filepath.Join(dir, "source.zip")
	if e = os.WriteFile(sourceFile, []byte("source"), 0600); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(dir, "export.zip")
	if e = postGravitInventory0333(server.URL+"/export", "test-token", sourceFile, destination, true); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(destination)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("export permissions %v %v", info, e)
	}
	if e = postGravitInventory0333(server.URL+"/export", "test-token", sourceFile, destination, true); e == nil {
		t.Fatal("clobbered an existing export")
	}
	if _, e = os.Stat(destination); e != nil {
		t.Fatal("old export lost")
	}
}
func TestGravitSourceCLIRejectsUnsafeTransport0333(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "source.zip")
	_ = os.WriteFile(p, []byte("zip"), 0600)
	e := postGravitInventory0333("http://example.org/export", "test-token", p, filepath.Join(dir, "out"), true)
	if e == nil || !strings.Contains(e.Error(), "HTTPS") {
		t.Fatalf("unsafe transport allowed: %v", e)
	}
}
func sha0333(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
