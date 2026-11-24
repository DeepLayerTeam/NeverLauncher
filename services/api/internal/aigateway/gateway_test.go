package aigateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeLedger struct {
	reserveErr, finishErr          error
	reserved, finished             int
	amount, charged, input, output int64
	state                          string
	finishContextErr               error
}

func (f *fakeLedger) Reserve(_ context.Context, r Reservation, _ Config) error {
	f.reserved++
	f.amount = r.Amount
	return f.reserveErr
}
func (f *fakeLedger) Finish(ctx context.Context, _ Reservation, s string, in, out, charge int64) error {
	f.finished++
	f.state = s
	f.input = in
	f.output = out
	f.charged = charge
	f.finishContextErr = ctx.Err()
	return f.finishErr
}
func (f *fakeLedger) Usage(context.Context, string, string) (Usage, error) { return Usage{}, nil }

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testConfig() Config {
	return Config{Key: "test-secret-not-real", Model: "test-model", Roles: map[string]bool{"player": true}, InputCeiling: 4096, OutputLimit: 128, InputRate: 1_000_000, OutputRate: 2_000_000, GlobalBudget: 100_000, UserBudget: 20_000, UserRPM: 3, MaxConcurrent: 1, Timeout: time.Second * 5}
}

const completed = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}}\n\n"

func testGateway(t *testing.T, l *fakeLedger, provider http.HandlerFunc) *Gateway {
	t.Helper()
	g := New(testConfig(), nil)
	g.ledger = l
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	g.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != endpoint {
			t.Errorf("unexpected upstream %s", r.URL)
		}
		clone := r.Clone(r.Context())
		target, _ := http.NewRequest(r.Method, srv.URL, r.Body)
		clone.URL = target.URL
		clone.Host = target.URL.Host
		return http.DefaultTransport.RoundTrip(clone)
	})
	return g
}
func TestStreamRealHTTPAndSettlement(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret-not-real" {
			t.Error("missing provider auth")
		}
		var p map[string]any
		if json.NewDecoder(r.Body).Decode(&p) != nil || p["model"] != "test-model" || p["input"] != "hi" || p["store"] != false || p["stream"] != true || p["max_output_tokens"] != float64(128) || p["service_tier"] != "default" || len(p) != 8 || p["tool_choice"] != "none" || len(p["tools"].([]any)) != 0 {
			t.Errorf("unexpected provider payload %#v", p)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, completed)
	})
	var events []string
	err := g.Stream(context.Background(), "user", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error {
		events = append(events, n)
		if n == "done" && (l.finished != 1 || e.ChargedMicroUSD != 18) {
			t.Error("done before accounting")
		}
		return nil
	})
	if err != nil || strings.Join(events, ",") != "start,delta,done" || l.state != "completed" || l.charged != 18 || l.amount != 4352 {
		t.Fatalf("err=%v events=%v ledger=%+v", err, events, l)
	}
}
func TestNoProviderBeforeAdmission(t *testing.T) {
	for _, cause := range []error{ErrBudget, ErrRate, errors.New("database offline")} {
		t.Run(cause.Error(), func(t *testing.T) {
			l := &fakeLedger{reserveErr: cause}
			g := testGateway(t, l, func(http.ResponseWriter, *http.Request) { t.Error("provider called") })
			e := g.Stream(context.Background(), "user", Request{Prompt: "hi"}, func() bool { return true }, func(string, Event) error { t.Error("emitted event"); return nil })
			if !errors.Is(e, cause) || l.finished != 0 {
				t.Fatal(e)
			}
		})
	}
}
func TestInterruptedAndInvalidProviderKeepReservation(t *testing.T) {
	for _, body := range []string{"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", "data: [DONE]\n\n", "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n", "data: malformed\n\n"} {
		t.Run(body, func(t *testing.T) {
			l := &fakeLedger{}
			g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, body)
			})
			last := ""
			e := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error { last = n; return nil })
			if e != nil || last != "error" || l.charged != l.amount || l.state != "uncertain" {
				t.Fatalf("%v %+v %s", e, l, last)
			}
		})
	}
}
func TestCancelledClientSettlementUsesIndependentContext(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, completed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = g.Stream(ctx, "u", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error {
		if n == "delta" {
			cancel()
			return context.Canceled
		}
		return nil
	})
	if l.finished != 1 || l.finishContextErr != nil || l.charged != l.amount {
		t.Fatalf("%+v", l)
	}
}
func TestAccountingFailureNeverEmitsDone(t *testing.T) {
	l := &fakeLedger{finishErr: errors.New("database down")}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, completed)
	})
	last := ""
	err := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error { last = n; return nil })
	if !errors.Is(err, ErrAccounting) || last != "error" || l.finished != 1 {
		t.Fatalf("%v %+v %s", err, l, last)
	}
}
func TestAccessDeniedBeforeAndDuringStream(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, completed)
	})
	emit := func(n string, e Event) error {
		if n == "delta" {
			t.Error("leaked delta")
		}
		return nil
	}
	if !errors.Is(g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return false }, emit), ErrAccess) || l.reserved != 0 {
		t.Fatal("unauthorized admission")
	}
	calls := 0
	_ = g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { calls++; return calls <= 2 }, emit)
	if l.state != "uncertain" || l.charged != l.amount {
		t.Fatalf("%+v", l)
	}
}
func TestProviderHTTPErrorSanitized(t *testing.T) {
	l := &fakeLedger{}
	g := testGateway(t, l, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "secret upstream error", 429) })
	err := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return true }, func(n string, e Event) error {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "secret") {
			t.Error("upstream secret leaked")
		}
		if n == "done" {
			t.Error("unexpected done")
		}
		return nil
	})
	if err != nil || l.charged != l.amount {
		t.Fatalf("%v %+v", err, l)
	}
}
func TestDecodeRequestRejectsOverrides(t *testing.T) {
	for _, s := range []string{`{"prompt":"hi","model":"expensive"}`, `{"prompt":"hi","tools":[]}`, `{"prompt":""}`, `{"prompt":"hi"}{}`, `null`, `{"prompt":12}`} {
		if _, e := DecodeRequest(strings.NewReader(s)); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	if p, e := DecodeRequest(strings.NewReader(`{"prompt":"привет"}`)); e != nil || p.Prompt != "привет" {
		t.Fatal(p, e)
	}
}
func TestConfigFailClosedAndCost(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if _, enabled, e := FromEnv(get); enabled || e != nil {
		t.Fatal("disabled config")
	}
	env["LAUNCHER_AI_ENABLED"] = "true"
	if _, _, e := FromEnv(get); e == nil {
		t.Fatal("accepted missing config")
	}
	for k, v := range map[string]string{"OPENAI_API_KEY": "test", "MODEL": "test-model", "ALLOWED_ROLES": "player,owner", "INPUT_TOKEN_CEILING": "4096", "INPUT_RATE_MICROUSD_PER_MILLION": "1000000", "OUTPUT_RATE_MICROUSD_PER_MILLION": "2000000", "MONTHLY_BUDGET_MICROUSD": "100000", "USER_MONTHLY_BUDGET_MICROUSD": "20000", "MAX_OUTPUT_TOKENS": "128"} {
		env["LAUNCHER_AI_"+k] = v
	}
	c, enabled, e := FromEnv(get)
	if e != nil || !enabled || c.ReserveCost() != 4352 || !c.Roles["player"] || c.Roles["admin"] {
		t.Fatalf("%v %t", e, enabled)
	}
	env["LAUNCHER_AI_USER_MONTHLY_BUDGET_MICROUSD"] = "1"
	if _, _, e := FromEnv(get); e == nil {
		t.Fatal("accepted inadequate budget")
	}
}
func TestParserIncompleteUsageAndMultiline(t *testing.T) {
	s := "event: response.incomplete\r\ndata: {\"type\":\"response.incomplete\",\r\ndata: \"response\":{\"status\":\"incomplete\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\r\n\r\n"
	out, e := parseStream(strings.NewReader(s), func(string, Event) error { return nil })
	if e != nil || !out.Known || out.State != "incomplete" || out.Input != 7 || out.Output != 9 {
		t.Fatal(out, e)
	}
}
func TestConcurrencySlot(t *testing.T) {
	l := &fakeLedger{}
	g := New(testConfig(), nil)
	g.ledger = l
	g.slots <- struct{}{}
	defer func() { <-g.slots }()
	if e := g.Stream(context.Background(), "u", Request{Prompt: "hi"}, func() bool { return true }, func(string, Event) error { return nil }); !errors.Is(e, ErrBusy) || l.reserved != 0 {
		t.Fatal(e)
	}
}
