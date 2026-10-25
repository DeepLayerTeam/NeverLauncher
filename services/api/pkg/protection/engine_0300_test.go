package protection

import (
	"context"
	"strings"
	"testing"
	"time"
)

type panicHandler0300 struct{ n string }

func (h panicHandler0300) Name() string { return h.n }
func (h panicHandler0300) Evaluate(context.Context, Request) (Decision, error) {
	panic("SECRET SHOULD NEVER APPEAR IN DECISION")
}

type cancelHandler0300 struct{ cancel context.CancelFunc }

func (h cancelHandler0300) Name() string { return "cancel-context" }
func (h cancelHandler0300) Evaluate(_ context.Context, _ Request) (Decision, error) {
	h.cancel()
	return Decision{Action: Allow, Reason: "test"}, nil
}

type timeoutHandler0300 struct{}

func (timeoutHandler0300) Name() string { return "timeout" }
func (timeoutHandler0300) Evaluate(ctx context.Context, _ Request) (Decision, error) {
	<-ctx.Done()
	return Decision{Action: Allow}, nil
}

func TestFailClosedOnCancelledPolicyContext0300(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := New(time.Second).Evaluate(ctx, Request{Stage: BeforeJoin}); d.Action != Deny || d.Reason != "policy_context_unavailable" {
		t.Fatalf("canceled policy allowed without handlers: %+v", d)
	}
	ctx, cancel = context.WithCancel(context.Background())
	engine := New(time.Second)
	if err := engine.Register(0, false, []Stage{BeforeJoin}, cancelHandler0300{cancel}); err != nil {
		t.Fatal(err)
	}
	if d := engine.Evaluate(ctx, Request{Stage: BeforeJoin}); d.Action != Deny {
		t.Fatalf("canceled policy allowed after optional handler: %+v", d)
	}
}

func TestMandatoryPanicAndTimeoutCannotGrantAccess0300(t *testing.T) {
	engine := New(time.Millisecond)
	if err := engine.Register(0, true, []Stage{BeforeAuth}, panicHandler0300{"untrusted"}); err != nil {
		t.Fatal(err)
	}
	d := engine.Evaluate(context.Background(), Request{Stage: BeforeAuth})
	if d.Action != Deny || d.Reason != "policy_handler_unavailable" || d.Handler != "untrusted" {
		t.Fatalf("panicking mandatory handler not denied: %+v", d)
	}
	if err := evaluatePanic0300(); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("handler panic must return a redacted error, got %v", err)
	}
	engine = New(time.Millisecond)
	if err := engine.Register(0, true, []Stage{BeforeAuth}, timeoutHandler0300{}); err != nil {
		t.Fatal(err)
	}
	if d := engine.Evaluate(context.Background(), Request{Stage: BeforeAuth}); d.Action != Deny {
		t.Fatalf("timeout granted access: %+v", d)
	}
}
func evaluatePanic0300() error {
	_, err := evaluateHandlerSafely(context.Background(), panicHandler0300{"untrusted"}, Request{})
	return err
}
