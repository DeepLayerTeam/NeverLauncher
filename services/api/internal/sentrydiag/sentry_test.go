package sentrydiag

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeAndPrivacy(t *testing.T) {
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/42/envelope/" || r.Header.Get("Content-Type") != "application/x-sentry-envelope" {
			t.Errorf("invalid ingestion request %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dsn := strings.Replace(srv.URL, "http://", "http://public@", 1) + "/42"
	reporter, err := New(dsn, "0.30.9+abc", "test")
	if err != nil {
		t.Fatal(err)
	}
	reporter.Capture("test", "backend", "bearer abc123 alice@example.com /home/alice /Users/bob 127.0.0.1")
	select {
	case raw := <-got:
		for _, s := range []string{"abc123", "alice@example.com", "/home/alice", "/Users/bob"} {
			if strings.Contains(raw, s) {
				t.Errorf("leak: %s", s)
			}
		}
		lines := strings.Split(strings.TrimSpace(raw), "\n")
		if len(lines) != 3 {
			t.Fatalf("bad envelope %d", len(lines))
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(lines[2]), &e); err != nil {
			t.Fatal(err)
		}
		if e["release"] != "0.30.9+abc" {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing envelope")
	}
	reporter.Close()
}
func TestHTTPWrapper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	r, e := New(strings.Replace(srv.URL, "http://", "http://abc@", 1)+"/4", "x", "test")
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	r.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) })).ServeHTTP(w, httptest.NewRequest("GET", "/token/supersecret", nil))
	if w.Code != 502 {
		t.Fatal(w.Code)
	}
	r.Close()
}
func TestBadDSNs(t *testing.T) {
	for _, dsn := range []string{"http://pub@example.com/4", "https://example.com/4", "https://pub@example.com/nope"} {
		if _, err := New(dsn, "x", "y"); err == nil {
			t.Fatal(dsn)
		}
	}
}
func TestSendContext(t *testing.T) {
	r, e := New("http://key@localhost:9/12", "r", "env")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.send(ctx, event{"a", "b", "c"}); err == nil {
		t.Fatal("canceled request succeeded")
	}
	r.Close()
}
