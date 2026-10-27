package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllowlistAndRemoteProtection(t *testing.T) {
	if _, e := safeURL("http://example.org/api/v1/status", false); e == nil {
		t.Fatal("remote without approval")
	}
	if _, e := safeURL("http://127.0.0.1:8080/api/v1/auth/login", false); e == nil {
		t.Fatal("write endpoint allowed")
	}
	if _, e := safeURL("http://127.0.0.1:8080/api/v1/status?token=private", false); e == nil {
		t.Fatal("token query allowed")
	}
	if _, e := safeURL("https://example.org/api/v1/status", true); e != nil {
		t.Fatal(e)
	}
}
func TestMeasuredSuccessAndFailures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	r := run(context.Background(), ts.Client(), ts.URL, 2, 120*time.Millisecond)
	if r.Requests < 10 || r.Successful != r.Requests || !r.Passed || r.RPS <= 0 {
		t.Fatalf("unmeasured success %+v", r)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	r = run(context.Background(), bad.Client(), bad.URL, 2, 120*time.Millisecond)
	if r.Status5xx == 0 || r.Passed {
		t.Fatalf("bad backend claimed capacity %+v", r)
	}
}

// Release-candidate regression: a login wall, redirect, or 4xx was previously
// incorrectly classified as sufficient capacity, despite zero successful GETs.
func TestProductionRCRejectsEveryUnexpectedResponse(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusFound, http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			client := srv.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			result := run(context.Background(), client, srv.URL, 2, 150*time.Millisecond)
			if result.Requests < 10 || result.Passed || result.Successful != 0 {
				t.Fatalf("unhealthy endpoint accepted: %+v", result)
			}
			if status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable && result.UnexpectedHTTP != result.Requests {
				t.Fatalf("unexpected HTTP status not accounted for: %+v", result)
			}
		})
	}
}

func TestProductionRCMixedSuccessAndErrorsFails(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1)%7 == 0 {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	result := run(context.Background(), srv.Client(), srv.URL, 4, 150*time.Millisecond)
	if result.Requests < 10 || result.UnexpectedHTTP == 0 || result.Successful == 0 || result.Passed {
		t.Fatalf("partial capacity accepted: %+v", result)
	}
}
