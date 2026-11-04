package sentrydiag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Заголовок авторизации приёма Sentry никогда не должен достигать origin,
// выбранного серверным редиректом, даже если злоумышленник перенаправляет на
// HTTPS.
func TestSentryIngestDoesNotFollowRedirect0498(t *testing.T) {
	var forwarded atomic.Int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		forwarded.Add(1)
		t.Errorf("Sentry envelope redirected with auth %q", req.Header.Get("X-Sentry-Auth"))
	}))
	defer attacker.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.Header.Get("X-Sentry-Auth"), "sentry_key=public") {
			t.Error("legitimate ingest missing public key")
		}
		http.Redirect(w, req, attacker.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	reporter, err := New(strings.Replace(source.URL, "http://", "http://public@", 1)+"/42", "0.49.8", "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := reporter.send(ctx, event{Category: "error", Component: "remote", Message: "redacted"}); err == nil {
		t.Fatal("redirect was silently accepted")
	}
	reporter.Close()
	if forwarded.Load() != 0 {
		t.Fatalf("envelope forwarded %d times", forwarded.Load())
	}
}
