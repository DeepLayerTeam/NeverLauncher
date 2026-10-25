package httpapi

import (
	"strings"
	"testing"
)

func TestHWIDRiskNeverAutomaticallyRevokes0299(t *testing.T) {
	for _, tc := range []struct {
		reasons    []string
		wantAction string
	}{
		{[]string{"hwid-signal-changed"}, "step-up"},
		{[]string{"ip-changed", "hwid-signal-changed"}, "step-up"},
		{[]string{"ip-changed", "user-agent-changed", "hwid-signal-changed"}, "step-up"},
		{[]string{"hwid-signal-changed", "refresh-token-reuse"}, "revoke"},
	} {
		_, _, action := evaluateRiskReasons0126(tc.reasons)
		if action != tc.wantAction {
			t.Errorf("%v: got %s want %s", tc.reasons, action, tc.wantAction)
		}
	}
}
func TestHWIDDigestIsAccountScoped0299(t *testing.T) {
	hint := strings.Repeat("f", 64)
	a := hwidAccountDigest0299("secret", "alice", hint)
	b := hwidAccountDigest0299("secret", "bob", hint)
	if a == b || a == hint || len(a) != 64 {
		t.Fatal("HWID digest must be keyed and account-scoped")
	}
	if a != hwidAccountDigest0299("secret", "alice", hint) {
		t.Fatal("not deterministic")
	}
}
