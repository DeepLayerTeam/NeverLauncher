package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/aigateway"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type unifiedTransport130 func(*http.Request) (*http.Response, error)

func (f unifiedTransport130) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unifiedAIFixture130 struct {
	gateway *aigateway.Gateway
	calls   atomic.Int32
	stalled chan struct{}
}

// Real gateway, HTTP transport and SQLite ledger. Only the external provider is
// substituted, by trusted Go test code; no environment flag enables a fake provider.
func newUnifiedAIFixture130(t *testing.T) *unifiedAIFixture130 {
	t.Helper()
	ctx := context.Background()
	var ledger *aigateway.Ledger
	if runtime.GOOS == "linux" {
		r, err := repository.OpenSQLiteHTTPRepository0372(ctx, filepath.Join(privateSQLiteTempDir(t), "unified.db"), "https://launcher.example.test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if e := r.Close(); e != nil {
				t.Error(e)
			}
		})
		ledger, err = r.AILedger(ctx)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		// Exercise the same SQL accounting on all platforms without claiming
		// durable filesystem certification outside Linux.
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() {
			if e := db.Close(); e != nil {
				t.Error(e)
			}
		})
		if err := aigateway.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		ledger = aigateway.NewSQLLedger(db)
	}
	fixture := &unifiedAIFixture130{stalled: make(chan struct{})}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fixture.calls.Add(1)
		var p map[string]any
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p["input"] != "hello" || p["store"] != false || p["tool_choice"] != "none" || r.Header.Get("Authorization") != "Bearer disposable-fixture-key" {
			t.Error("provider request violated fixed security policy")
			w.WriteHeader(400)
			return
		}
		if n == 3 {
			close(fixture.stalled)
			select {
			case <-r.Context().Done():
			case <-time.After(20 * time.Second):
				t.Error("provider stream was not cancelled")
			}
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}}\n\n")
	}))
	t.Cleanup(provider.Close)
	target, err := url.Parse(provider.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := aigateway.Config{Key: "disposable-fixture-key", Model: "fixture", Roles: map[string]bool{"owner": true}, InputCeiling: 4096, OutputLimit: 128, InputRate: 1_000_000, OutputRate: 2_000_000, UserBudget: 5000, GlobalBudget: 10000, UserRPM: 20, MaxConcurrent: 2, Timeout: 25 * time.Second}
	fixture.gateway = aigateway.NewWithTransport(cfg, ledger, unifiedTransport130(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.openai.com/v1/responses" {
			t.Error("wrong upstream URL")
		}
		req := r.Clone(r.Context())
		req.URL = target
		req.Host = target.Host
		return http.DefaultTransport.RoundTrip(req)
	}))
	return fixture
}

func (f *unifiedAIFixture130) stream(t *testing.T, server *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/ai/responses", strings.NewReader(`{"prompt":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		res.Body.Close()
		t.Fatalf("expected SSE, got %d", res.StatusCode)
	}
	return res
}
func (f *unifiedAIFixture130) complete(t *testing.T, server *httptest.Server, token string) {
	t.Helper()
	res := f.stream(t, server, token)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil || !strings.Contains(string(body), "event: done") || !strings.Contains(string(body), `"chargedMicroUsd":18`) || strings.Contains(string(body), "event: error") {
		t.Fatalf("generation failed: %s %v", body, err)
	}
}
