package aigateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSensitiveInputNeverReservesOrDispatches(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(http.ResponseWriter, *http.Request) { t.Error("unexpected provider call") })
	for _, p := range []string{"sk-proj-" + strings.Repeat("x", 32), "Bearer " + strings.Repeat("x", 20), `{"password":"example-secret"}`, `{"question":"password=example-secret"}`, `{"question":"{\"access_token\":\"example-secret\"}"}`, "-----BEGIN PRIVATE KEY-----", "eyJabcdefgh.abcdefghijk.abcdefghijk", g.cfg.Key} {
		if e := g.Stream(context.Background(), "user", Request{Prompt: p}, func() bool { return true }, func(string, Event) error { t.Error("unexpected event"); return nil }); !errors.Is(e, ErrSensitive) {
			t.Error("credential pattern not blocked")
		}
	}
	if l.reserved != 0 {
		t.Fatal("secret reserved budget")
	}
	if sensitivePrompt("How do I configure a password?", g.cfg.Key) {
		t.Fatal("ordinary question blocked")
	}
}
func TestStrictRequestShape125(t *testing.T) {
	for _, raw := range []string{`{"prompt":"one","prompt":"two"}`, `{"Prompt":"hi"}`, `{"prompt":"hi","tool_choice":"auto"}`, `{"prompt":null}`, `[]`} {
		if _, e := DecodeRequest(strings.NewReader(raw)); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
func TestUnexpectedToolsAndOutputLimit125(t *testing.T) {
	for _, body := range []string{
		`data: {"type":"response.output_item.added","item":{"type":"function_call"}}` + "\n\n" + completed,
		`data: {"type":"response.function_call_arguments.delta","delta":"{}"}` + "\n\n" + completed,
		`data: {"type":"response.completed","response":{"status":"completed","output":[{"type":"web_search_call"}],"usage":{"input_tokens":10,"output_tokens":4}}}` + "\n\n",
		fmt.Sprintf("data: {\"type\":\"response.output_text.delta\",\"delta\":%q}\n\n", strings.Repeat("x", 131073)) + completed,
	} {
		n := 0
		out, e := parseStream(strings.NewReader(body), func(string, Event) error { n++; return nil })
		if !errors.Is(e, ErrProvider) || out.Known || n != 0 {
			t.Fatalf("unexpected result: %+v %v events=%d", out, e, n)
		}
	}
}
func TestRateLimitCooldownNoSecondPaidRequest(t *testing.T) {
	l := &fakeLedger{}
	calls := 0
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	})
	var last Event
	run := func() error {
		return g.Stream(context.Background(), "user", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error { last = e; return nil })
	}
	if e := run(); e != nil || last.Code != "provider_rate_limited" || l.charged != l.amount {
		t.Fatalf("%v %+v", e, last)
	}
	if e := run(); !errors.Is(e, ErrCoolingDown) || calls != 1 || l.reserved != 1 {
		t.Fatalf("%v %d %d", e, calls, l.reserved)
	}
	g.gate.mu.Lock()
	remaining := time.Until(g.gate.until)
	g.gate.mu.Unlock()
	if remaining < 110*time.Second || remaining > 120*time.Second {
		t.Fatal(remaining)
	}
}
func TestProviderFailuresCooldownAndProbe(t *testing.T) {
	l := &fakeLedger{}
	calls := 0
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 3 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, completed)
	})
	run := func() error {
		return g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return true }, func(string, Event) error { return nil })
	}
	for i := 0; i < 3; i++ {
		if e := run(); e != nil {
			t.Fatal(e)
		}
	}
	if e := run(); !errors.Is(e, ErrCoolingDown) || calls != 3 || l.reserved != 3 {
		t.Fatal(e, calls, l.reserved)
	}
	g.gate.mu.Lock()
	g.gate.until = time.Now().Add(-time.Second)
	g.gate.mu.Unlock()
	if e := run(); e != nil || l.state != "completed" {
		t.Fatal(e, l.state)
	}
	if e := run(); e != nil || calls != 5 {
		t.Fatal(e, calls)
	}
}
func TestProbeCannotBeReleasedByOlderRequest(t *testing.T) {
	var g providerGate
	now := time.Now()
	g.result(now, false, ErrUpstreamRate, 0)
	later := now.Add(time.Minute)
	allowed, probe := g.enter(later)
	if !allowed || !probe {
		t.Fatal("probe denied")
	}
	g.abandon(false)
	g.result(later, false, nil, 0)
	if allowed, _ := g.enter(later); allowed {
		t.Fatal("concurrent probe admitted")
	}
	g.result(later, true, nil, 0)
	if allowed, probe := g.enter(later); !allowed || probe {
		t.Fatal("not recovered")
	}
}
func TestTerminalWithoutDeltaStillChecksAccess(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, strings.SplitN(completed, "\n\n", 2)[1])
	})
	calls := 0
	last := ""
	e := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { calls++; return calls <= 2 }, func(n string, e Event) error { last = n; return nil })
	if e != nil || last != "error" || l.state != "incomplete" || l.charged != 18 {
		t.Fatalf("%v %s %+v", e, last, l)
	}
}

func TestStalledProviderStopsOnRevocation(t *testing.T) {
	l := &fakeLedger{}
	disconnected := make(chan struct{})
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(disconnected)
	})
	g.cfg.Timeout = 12 * time.Second
	g.client.Timeout = 12 * time.Second
	began := time.Now()
	checks := 0
	last := Event{}
	e := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { checks++; return checks <= 2 }, func(n string, event Event) error { last = event; return nil })
	if e != nil || last.Code != "access_revoked" || l.charged != l.amount || time.Since(began) > 10*time.Second {
		t.Fatalf("%v %+v %+v", e, last, l)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("upstream not cancelled")
	}
}
