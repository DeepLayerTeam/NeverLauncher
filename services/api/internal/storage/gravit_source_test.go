package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGravitS3Source02510(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/bucket/skins/hash.png" || r.Header.Get("Authorization") == "" {
			t.Errorf("unsigned/misrouted request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "invalid", 401)
			return
		}
		_, _ = io.WriteString(w, "source-image")
	}))
	defer server.Close()
	src, err := NewS3Storage(S3Config{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "test", SecretKey: "test", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := src.OpenGravitSourceObject02510(context.Background(), "skins/hash.png")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(body) != "source-image" {
		t.Fatalf("read failed: %s %v", body, err)
	}
	for _, key := range []string{"../secret", "/secret", "skin\\secret", "a//b", "a/../b"} {
		if f, err := src.OpenGravitSourceObject02510(context.Background(), key); err == nil {
			f.Close()
			t.Fatalf("unsafe key accepted: %q", key)
		}
	}
}
func TestGravitS3RedirectRejected02510(t *testing.T) {
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("SSRF: redirected to arbitrary HTTP server") }))
	defer dst.Close()
	srcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL+"/private", http.StatusFound)
	}))
	defer srcServer.Close()
	src, err := NewS3Storage(S3Config{Endpoint: srcServer.URL, Bucket: "bucket", AccessKey: "test", SecretKey: "test", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	f, err := src.OpenGravitSourceObject02510(context.Background(), "skins/abc.png")
	if err == nil {
		f.Close()
		t.Fatal("redirect accepted")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("unexpected redirect failure: %v", err)
	}
}
