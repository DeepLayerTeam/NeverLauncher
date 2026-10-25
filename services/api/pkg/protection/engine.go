// Package protection is the runtime policy execution API. A mandatory handler
// error denies access; extension handlers cannot override an earlier denial.
package protection

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Stage string

const (
	BeforeAuth   Stage = "before-auth"
	AfterAuth    Stage = "after-auth"
	BeforeLaunch Stage = "before-launch"
	BeforeJoin   Stage = "before-join"
)

type Action string

const (
	Allow    Action = "allow"
	Deny     Action = "deny"
	StepUp   Action = "step-up"
	Reattest Action = "reattest"
	Review   Action = "review"
)

type Request struct {
	Stage     Stage
	UserID    string
	SessionID string
	DeviceID  string
	RoleID    string
	ProjectID string
	Issuer    string
}
type Decision struct {
	Action  Action `json:"action"`
	Reason  string `json:"reason"`
	Handler string `json:"handler"`
}

func (d Decision) Allowed() bool { return d.Action == Allow }

type Handler interface {
	Name() string
	Evaluate(context.Context, Request) (Decision, error)
}
type entry struct {
	priority  int
	mandatory bool
	stages    map[Stage]bool
	handler   Handler
}
type Engine struct {
	mu       sync.RWMutex
	handlers []entry
	timeout  time.Duration
}

func New(timeout time.Duration) *Engine {
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 3 * time.Second
	}
	return &Engine{timeout: timeout}
}
func supported(s Stage) bool {
	switch s {
	case BeforeAuth, AfterAuth, BeforeLaunch, BeforeJoin:
		return true
	}
	return false
}
func (e *Engine) Register(priority int, mandatory bool, stages []Stage, h Handler) error {
	if e == nil || h == nil || strings.TrimSpace(h.Name()) == "" || len(stages) == 0 {
		return errors.New("invalid protection handler")
	}
	match := make(map[Stage]bool, len(stages))
	for _, s := range stages {
		if !supported(s) {
			return fmt.Errorf("unknown protection stage %q", s)
		}
		match[s] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, existing := range e.handlers {
		if existing.handler.Name() == h.Name() {
			return errors.New("duplicate protection handler")
		}
	}
	e.handlers = append(e.handlers, entry{priority: priority, mandatory: mandatory, stages: match, handler: h})
	sort.SliceStable(e.handlers, func(i, j int) bool { return e.handlers[i].priority < e.handlers[j].priority })
	return nil
}
func (e *Engine) Evaluate(ctx context.Context, req Request) Decision {
	if e == nil || !supported(req.Stage) {
		return Decision{Action: Deny, Reason: "policy_engine_unavailable", Handler: "engine"}
	}
	e.mu.RLock()
	handlers := append([]entry(nil), e.handlers...)
	timeout := e.timeout
	e.mu.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return Decision{Action: Deny, Reason: "policy_context_unavailable", Handler: "engine"}
	}
	for _, h := range handlers {
		if !h.stages[req.Stage] {
			continue
		}
		if ctx.Err() != nil {
			return Decision{Action: Deny, Reason: "policy_context_unavailable", Handler: "engine"}
		}
		scoped, cancel := context.WithTimeout(ctx, timeout)
		// Handlers run synchronously: timeout-aware storage/network handlers must
		// honor the context, without creating unbounded goroutines on timeout.
		// Untrusted extension panics are failures, never successful authorizations.
		decision, err := evaluateHandlerSafely(scoped, h.handler, req)
		deadlineErr := scoped.Err()
		cancel()
		if err != nil || deadlineErr != nil {
			if h.mandatory {
				return Decision{Action: Deny, Reason: "policy_handler_unavailable", Handler: h.handler.Name()}
			}
			continue
		}
		switch decision.Action {
		case Allow:
			continue
		case Deny, StepUp, Reattest, Review:
			if strings.TrimSpace(decision.Reason) == "" {
				return Decision{Action: Deny, Reason: "policy_reason_missing", Handler: h.handler.Name()}
			}
			decision.Handler = h.handler.Name()
			return decision
		default:
			return Decision{Action: Deny, Reason: "invalid_policy_decision", Handler: h.handler.Name()}
		}
	}
	if ctx.Err() != nil {
		return Decision{Action: Deny, Reason: "policy_context_unavailable", Handler: "engine"}
	}
	return Decision{Action: Allow, Reason: "policy_approved", Handler: "engine"}
}

func evaluateHandlerSafely(ctx context.Context, handler Handler, req Request) (decision Decision, err error) {
	defer func() {
		if recover() != nil {
			// Do not log/re-emit panic payloads: extensions may panic with secrets.
			decision = Decision{}
			err = errors.New("protection handler panicked")
		}
	}()
	return handler.Evaluate(ctx, req)
}
