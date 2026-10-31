package officialminecraft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMojangProfileTransientRetry0427(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/minecraft/profile" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		n := calls.Add(1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"slow_down"}`))
			return
		}
		w.Write([]byte(`{"id":"123456781234123412341234567890ab","name":"Player"}`))
	}))
	defer server.Close()
	c := New()
	c.minecraft = server.URL
	p, err := c.Profile(context.Background(), "token")
	if err != nil || p.Name != "Player" || calls.Load() != 3 {
		t.Fatalf("profile retry %+v %v count=%d", p, err, calls.Load())
	}
}
func TestMojangWritesNeverAutomaticallyRetried0427(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"temporarily_unavailable"}`))
	}))
	defer server.Close()
	c := New()
	c.microsoft = server.URL
	_, err := c.Complete(context.Background(), "client", "device-code")
	if err == nil || !strings.Contains(err.Error(), "temporarily_unavailable") || calls.Load() != 1 {
		t.Fatalf("POST retried %v %d", err, calls.Load())
	}
}
