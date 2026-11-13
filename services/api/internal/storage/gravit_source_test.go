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
			t.Errorf("Неподписанный либо неверно маршрутизированный запрос: %s %s", r.Method, r.URL.Path)
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
		t.Fatalf("Ошибка чтения %s: %v", body, err)
	}
	for _, key := range []string{"../secret", "/secret", "skin\\secret", "a//b", "a/../b"} {
		if f, err := src.OpenGravitSourceObject02510(context.Background(), key); err == nil {
			f.Close()
			t.Fatalf("Принят небезопасный ключ: %q", key)
		}
	}
}
func TestGravitS3RedirectRejected02510(t *testing.T) {
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SSRF: перенаправление на произвольный HTTP-сервер")
	}))
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
		t.Fatal("Небезопасное перенаправление принято")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("Неожиданная ошибка перенаправления: %v", err)
	}
}
