package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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
