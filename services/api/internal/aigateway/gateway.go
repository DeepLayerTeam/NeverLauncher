package aigateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const endpoint = "https://api.openai.com/v1/responses"
const MaxPromptBytes = 16384
const maxEventBytes = 1 << 20
const maxStreamBytes = 32 << 20

// Gateway owns the provider credential and restricts the entire upstream request.
// No user-supplied URL, model, tools, instructions, service tier or token limit.
type accounting interface {
	Reserve(context.Context, Reservation, Config) error
	Finish(context.Context, Reservation, string, int64, int64, int64) error
	Usage(context.Context, string, string) (Usage, error)
}
type Gateway struct {
	cfg    Config
	ledger accounting
	client *http.Client
	slots  chan struct{}
}

func New(c Config, l *Ledger) *Gateway {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 30 * time.Second
	tr.MaxConnsPerHost = c.MaxConcurrent
	return &Gateway{cfg: c, ledger: l, client: &http.Client{Transport: tr, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, slots: make(chan struct{}, c.MaxConcurrent)}
}
func (g *Gateway) Allowed(role string) bool { return g.cfg.Roles[role] }
func (g *Gateway) Model() string            { return g.cfg.Model }
func (g *Gateway) Usage(ctx context.Context, user string) (Usage, error) {
	return g.ledger.Usage(ctx, time.Now().UTC().Format("2006-01"), user)
}
func (g *Gateway) Budget(user bool) int64 {
	if user {
		return g.cfg.UserBudget
	}
	return g.cfg.GlobalBudget
}

type Request struct {
	Prompt string `json:"prompt"`
}

func DecodeRequest(r io.Reader) (Request, error) {
	var p Request
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, errors.New("expected one JSON object")
	}
	if !utf8.ValidString(p.Prompt) || strings.TrimSpace(p.Prompt) == "" || len(p.Prompt) > MaxPromptBytes {
		return p, errors.New("invalid prompt")
	}
	return p, nil
}

type Event struct {
	RequestID       string `json:"requestId,omitempty"`
	Delta           string `json:"delta,omitempty"`
	Code            string `json:"code,omitempty"`
	InputTokens     int64  `json:"inputTokens,omitempty"`
	OutputTokens    int64  `json:"outputTokens,omitempty"`
	ChargedMicroUSD int64  `json:"chargedMicroUsd,omitempty"`
	State           string `json:"state,omitempty"`
}
type Emit func(string, Event) error
type Outcome struct {
	State         string
	Input, Output int64
	Known         bool
}

var ErrBusy = errors.New("AI gateway busy")
var ErrInvalid = errors.New("AI prompt exceeds configured limit")
var ErrAccess = errors.New("AI access revoked")
var ErrProvider = errors.New("AI provider failed")
var ErrAccounting = errors.New("AI accounting unavailable")

// Stream returns errors before the first event as HTTP errors; after admission,
// emits a sanitized terminal SSE event only after accounting is persisted.
func (g *Gateway) Stream(ctx context.Context, user string, p Request, check func() bool, emit Emit) (err error) {
	if user == "" || strings.TrimSpace(p.Prompt) == "" || len(p.Prompt) > MaxPromptBytes || int64(len(p.Prompt))+256 > g.cfg.InputCeiling {
		return ErrInvalid
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return ErrBusy
	}
	if !check() {
		return ErrAccess
	}
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	now := time.Now().UTC()
	r := Reservation{ID: hex.EncodeToString(id[:]), User: user, Month: now.Format("2006-01"), Model: g.cfg.Model, Started: now.Unix(), Amount: g.cfg.ReserveCost()}
	if err = g.ledger.Reserve(ctx, r, g.cfg); err != nil {
		return err
	}
	outcome := Outcome{State: "incomplete", Known: true}
	charge := r.Amount
	settlementAttempted := false
	finish := func() error {
		settlementAttempted = true
		if outcome.Known {
			charge = g.cfg.Cost(outcome.Input, outcome.Output)
		}
		// The request context may already be cancelled by the client. Never release
		// reservation on unknown usage or a failed database commit.
		fc, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e := g.ledger.Finish(fc, r, outcome.State, outcome.Input, outcome.Output, charge); e != nil {
			return ErrAccounting
		}
		return nil
	}
	defer func() {
		if !settlementAttempted {
			_ = finish()
		}
	}()
	if err = emit("start", Event{RequestID: r.ID}); err != nil {
		return err
	}
	if !check() { // No provider request has been made, known zero charge.
		outcome = Outcome{State: "incomplete", Known: true}
		if e := finish(); e != nil {
			return e
		}
		return emit("error", Event{Code: "access_revoked", State: outcome.State})
	}
	outcome = Outcome{State: "uncertain"}
	outcome, err = g.call(ctx, p, check, emit)
	if e := finish(); e != nil {
		_ = emit("error", Event{Code: "accounting_unavailable", State: "uncertain"})
		return e
	}
	terminal := Event{RequestID: r.ID, InputTokens: outcome.Input, OutputTokens: outcome.Output, ChargedMicroUSD: charge, State: outcome.State}
	if err != nil || outcome.State != "completed" {
		terminal.Code = "provider_incomplete"
		if errors.Is(err, ErrAccess) {
			terminal.Code = "access_revoked"
		}
		if ctx.Err() != nil {
			terminal.Code = "stream_cancelled"
		}
		return emit("error", terminal)
	}
	return emit("done", terminal)
}

func (g *Gateway) call(ctx context.Context, p Request, check func() bool, emit Emit) (Outcome, error) {
	unknown := Outcome{State: "uncertain"}
	body, err := json.Marshal(map[string]any{"model": g.cfg.Model, "input": p.Prompt, "stream": true, "store": false, "max_output_tokens": g.cfg.OutputLimit, "service_tier": "default"})
	if err != nil {
		return unknown, ErrProvider
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return unknown, ErrProvider
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	// POST is never retried by application code; a failed call may be billable.
	res, err := g.client.Do(req)
	if err != nil {
		return unknown, ErrProvider
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return unknown, ErrProvider
	}
	typ, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || typ != "text/event-stream" {
		return unknown, ErrProvider
	}
	lastCheck := time.Now().Add(-5 * time.Second)
	return parseStream(res.Body, func(name string, e Event) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(lastCheck) >= 5*time.Second {
			if !check() {
				return ErrAccess
			}
			lastCheck = time.Now()
		}
		return emit(name, e)
	})
}

type providerEvent struct {
	Type     string `json:"type"`
	Delta    string `json:"delta"`
	Response *struct {
		Status string `json:"status"`
		Usage  *struct {
			Input  *int64 `json:"input_tokens"`
			Output *int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"response"`
}

func parseStream(r io.Reader, emit Emit) (Outcome, error) {
	unknown := Outcome{State: "uncertain"}
	scan := bufio.NewScanner(io.LimitReader(r, maxStreamBytes+1))
	scan.Buffer(make([]byte, 4096), maxEventBytes)
	var data strings.Builder
	total := 0
	for scan.Scan() {
		line := scan.Text()
		total += len(line) + 1
		if total > maxStreamBytes {
			return unknown, ErrProvider
		}
		if line != "" {
			if strings.HasPrefix(line, "data:") {
				v := strings.TrimPrefix(line, "data:")
				v = strings.TrimPrefix(v, " ")
				if data.Len()+len(v)+1 > maxEventBytes {
					return unknown, ErrProvider
				}
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(v)
			}
			continue
		}
		if data.Len() == 0 {
			continue
		}
		payload := data.String()
		data.Reset()
		if payload == "[DONE]" {
			return unknown, ErrProvider
		} // Never infer completion without usage.
		var e providerEvent
		if json.Unmarshal([]byte(payload), &e) != nil || e.Type == "" {
			return unknown, ErrProvider
		}
		switch e.Type {
		case "response.output_text.delta", "response.refusal.delta":
			if e.Delta != "" {
				if err := emit("delta", Event{Delta: e.Delta}); err != nil {
					return unknown, err
				}
			}
		case "response.completed", "response.incomplete", "response.failed":
			if e.Response == nil || e.Response.Usage == nil || e.Response.Usage.Input == nil || e.Response.Usage.Output == nil {
				return unknown, ErrProvider
			}
			in, out := *e.Response.Usage.Input, *e.Response.Usage.Output
			if in < 0 || out < 0 || in > 100_000_000 || out > 100_000_000 {
				return unknown, ErrProvider
			}
			state := "incomplete"
			if e.Type == "response.completed" && e.Response.Status == "completed" {
				state = "completed"
			}
			return Outcome{State: state, Input: in, Output: out, Known: true}, nil
		case "error":
			return unknown, ErrProvider
		}
	}
	return unknown, fmt.Errorf("%w: missing terminal usage", ErrProvider)
}
