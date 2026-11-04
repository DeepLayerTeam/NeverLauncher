package neverapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRealStreamingMultipartAndBinary0463(t *testing.T) {
	payload := bytes.Repeat([]byte{0x00, 0xff, 0x01, 0x89}, 3<<20) // 12 MiB, above the old 8 MiB buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/projects/one/versions/two/files" {
			t.Errorf("path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("Idempotency-Key") != "upload-1" || r.Header.Get("Content-Type") != "multipart/form-data; boundary=fixed" {
			t.Error("request headers")
		}
		if r.URL.Query().Get("source") != "integration" {
			t.Error("query params")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(b, payload) {
			t.Error("streaming body mismatch", err)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	c, err := New(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	n, err := c.CallStream(context.Background(), "post_admin_projects_by_projectId_versions_by_versionId_files", map[string]string{"projectId": "one", "versionId": "two"}, url.Values{"source": {"integration"}}, bytes.NewReader(payload), "multipart/form-data; boundary=fixed", &out, 20<<20, "upload-1")
	if err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("transfer failed n=%d err=%v", n, err)
	}
	var limited bytes.Buffer
	_, err = c.RequestStream(context.Background(), "POST", "/api/v1/admin/projects/one/versions/two/files", url.Values{"source": {"integration"}}, bytes.NewReader(payload), "multipart/form-data; boundary=fixed", &limited, 100, "upload-1")
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("limit bypass: %v", err)
	}
}

func TestStreamRejectsRedirectAndInvalidOptions0463(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("redirect followed with token") }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	}))
	defer server.Close()
	c, _ := New(server.URL, "secret")
	// Custom redirect-following HTTP client must not weaken this SDK API.
	c.HTTP = &http.Client{}
	var out bytes.Buffer
	_, err := c.RequestStream(context.Background(), "GET", "/api/v1/redirect", nil, nil, "", &out, 1024, "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 307 {
		t.Fatalf("redirect accepted: %v", err)
	}
	if _, err = c.RequestStream(context.Background(), "GET", "/api/v1/a", nil, nil, "", nil, 1024, ""); err == nil {
		t.Fatal("nil writer accepted")
	}
	if _, err = c.RequestStream(context.Background(), "GET", "/api/v1/a", nil, nil, "", &out, -1, ""); err == nil {
		t.Fatal("negative limit accepted")
	}
	if _, err = c.RequestStream(context.Background(), "GET", "//evil", nil, nil, "", &out, 1024, ""); err == nil {
		t.Fatal("unsafe path accepted")
	}
}

func TestExistingJSONAndRawSDKDoNotFollowRedirects0463(t *testing.T) {
	var redirected bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true; w.WriteHeader(200) }))
	defer attacker.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", attacker.URL)
		w.WriteHeader(307)
	}))
	defer api.Close()
	c, _ := New(api.URL, "secret")
	c.HTTP = &http.Client{}
	err := c.Request(context.Background(), "GET", "/api/v1/projects", nil, nil, nil, "")
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != 307 {
		t.Fatalf("JSON followed redirect: %v", err)
	}
	_, err = c.CallRaw(context.Background(), "get_projects", nil, nil, nil, "", "")
	if !errors.As(err, &apiError) || apiError.Status != 307 {
		t.Fatalf("binary followed redirect: %v", err)
	}
	if redirected {
		t.Fatal("bearer token was sent to redirect target")
	}
}
