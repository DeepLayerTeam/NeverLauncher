package neverapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPClientRealRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			w.Header().Set("X-Launcher-API-Contract", "1.0.0")
			json.NewEncoder(w).Encode(map[string]any{"version": "0.45.12"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Error("missing token")
		}
		if r.URL.Path == "/api/v1/admin/projects/one/versions/two/files" {
			if r.Header.Get("Content-Type") != "application/octet-stream" {
				t.Errorf("wrong content type")
			}
			var b [3]byte
			_, _ = r.Body.Read(b[:])
			w.Write(b[:])
			return
		}
		if r.URL.EscapedPath() == "/api/v1/projects/a%20b" && r.URL.Query().Get("page") == "1" {
			json.NewEncoder(w).Encode(map[string]string{"id": "a b"})
			return
		}
		w.Header().Set("X-Correlation-ID", "id-1")
		w.WriteHeader(403)
		w.Write([]byte(`{"code":"denied","message":"forbidden"}`))
	}))
	defer server.Close()
	c, err := New(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.CheckCompatibility(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err = c.Call(context.Background(), "get_projects_by_projectId", map[string]string{"projectId": "a b"}, url.Values{"page": {"1"}}, nil, &got, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := c.CallRaw(context.Background(), "post_admin_projects_by_projectId_versions_by_versionId_files", map[string]string{"projectId": "one", "versionId": "two"}, nil, []byte("xyz"), "application/octet-stream", "safe-key")
	if err != nil || string(raw) != "xyz" {
		t.Fatalf("raw err %v bytes %q", err, raw)
	}
	if got["id"] != "a b" {
		t.Fatal(got)
	}
	err = c.Call(context.Background(), "get_projects", nil, nil, nil, nil, "")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "denied" || ae.RequestID != "id-1" {
		t.Fatal(err)
	}
	if _, err = Path("/a/{projectId}", map[string]string{"projectId": "../admin"}); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err = New("http://example.org", "secret"); err == nil {
		t.Fatal("remote cleartext accepted")
	}
	if err = c.Request(context.Background(), "GET", "//evil", nil, nil, nil, ""); err == nil {
		t.Fatal("unsafe route")
	}
	if len(Operations) < 450 {
		t.Fatalf("missing operations %d", len(Operations))
	}
}
func TestLegacyAndIncompatible(t *testing.T) {
	for _, v := range []string{"0.45.11", "0.45.10"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"` + v + `"}`)) }))
		c, _ := New(server.URL, "")
		err := c.CheckCompatibility(context.Background())
		server.Close()
		if (err == nil) != (v == "0.45.11") {
			t.Fatalf("version %s err %v", v, err)
		}
	}
	if !strings.Contains(ContractVersion, "1.") {
		t.Fatal(ContractVersion)
	}
}
