package protection

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testHandler struct {
	name   string
	action Action
	err    error
}

func (h testHandler) Name() string { return h.name }
func (h testHandler) Evaluate(_ context.Context, _ Request) (Decision, error) {
	return Decision{Action: h.action, Reason: "test"}, h.err
}
func TestPolicyRuntime0298(t *testing.T) {
	e := New(time.Second)
	if err := e.Register(10, true, []Stage{BeforeAuth, BeforeJoin}, testHandler{"block", Deny, nil}); err != nil {
		t.Fatal(err)
	}
	if err := e.Register(20, true, []Stage{BeforeAuth}, testHandler{"allow", Allow, nil}); err != nil {
		t.Fatal(err)
	}
	if got := e.Evaluate(context.Background(), Request{Stage: BeforeAuth}); got.Action != Deny || got.Handler != "block" {
		t.Fatalf("denial overriden: %+v", got)
	}
	if got := e.Evaluate(context.Background(), Request{Stage: BeforeLaunch}); !got.Allowed() {
		t.Fatalf("unconfigured stage: %+v", got)
	}
	if err := e.Register(2, true, []Stage{BeforeAuth}, testHandler{"broken", Allow, errors.New("database unavailable")}); err != nil {
		t.Fatal(err)
	}
	if got := e.Evaluate(context.Background(), Request{Stage: BeforeAuth}); got.Action != Deny || got.Reason != "policy_handler_unavailable" {
		t.Fatalf("fail open: %+v", got)
	}
	if err := e.Register(2, true, []Stage{BeforeAuth}, testHandler{"broken", Allow, nil}); err == nil {
		t.Fatal("duplicate handler accepted")
	}
	if err := e.Register(2, true, []Stage{"bogus"}, testHandler{"bad", Allow, nil}); err == nil {
		t.Fatal("unknown stage accepted")
	}
}
