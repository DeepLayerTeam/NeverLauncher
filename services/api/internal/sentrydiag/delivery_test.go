package sentrydiag

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRetryTransientSentryIngestKeepsEventIdentity(t *testing.T) {
	var mu sync.Mutex
	ids := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if len(lines) != 3 {
			t.Errorf("bad envelope %q", body)
			w.WriteHeader(400)
			return
		}
		var e struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal([]byte(lines[2]), &e); err != nil {
			t.Error(err)
		}
		mu.Lock()
		ids = append(ids, e.EventID)
		attempt := len(ids)
		mu.Unlock()
		if attempt == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r, err := New(strings.Replace(srv.URL, "http://", "http://public@", 1)+"/42", "0.42.9", "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.send(ctx, event{"errors", "backend", "safe"}); err != nil {
		t.Fatal(err)
	}
	r.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] {
		t.Fatalf("retry did not preserve event identity: %v", ids)
	}
}

func TestCloseFlushesAcceptedEvents(t *testing.T) {
	var mu sync.Mutex
	got := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if len(lines) != 3 {
			t.Errorf("invalid envelope")
			return
		}
		var e struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(lines[2]), &e); err != nil {
			t.Error(err)
		}
		mu.Lock()
		got[e.Message] = true
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r, err := New(strings.Replace(srv.URL, "http://", "http://public@", 1)+"/42", "0.42.9", "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"alpha", "beta", "gamma", "delta"} {
		r.Capture("errors", "backend", msg)
	}
	r.Close()
	mu.Lock()
	defer mu.Unlock()
	for _, msg := range []string{"alpha", "beta", "gamma", "delta"} {
		if !got["errors: "+msg] {
			t.Errorf("lost queued event %s", msg)
		}
	}
	// A close is idempotent and later events cannot be accepted.
	r.Capture("errors", "backend", "late")
	r.Close()
}
