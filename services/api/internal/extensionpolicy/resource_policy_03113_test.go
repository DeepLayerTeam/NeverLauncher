package extensionpolicy

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"testing"
)

func TestResourcePolicy03113SignedQuotaAndReview(t *testing.T) {
	base := signedPolicy0318()
	before, _ := ApprovalDigest(base)
	policy := *base.Sandbox
	policy.MaxRequestsPerSecond = 4
	policy.MaxOutputBytes = 4096
	base.Sandbox = &policy
	if _, err := Validate(base.Sandbox); err != nil {
		t.Fatal(err)
	}
	after, err := ApprovalDigest(base)
	if err != nil || before == after {
		t.Fatal("quota did not alter signed approval digest", err)
	}
	for _, edit := range []func(*model.ExtensionSandboxPolicy){func(p *model.ExtensionSandboxPolicy) { p.MaxRequestsPerSecond = 65 }, func(p *model.ExtensionSandboxPolicy) { p.MaxRequestsPerSecond = -1 }, func(p *model.ExtensionSandboxPolicy) { p.MaxOutputBytes = 8<<20 + 1 }, func(p *model.ExtensionSandboxPolicy) { p.MaxOutputBytes = -1 }} {
		mutated := policy
		edit(&mutated)
		if _, err := Validate(&mutated); err == nil {
			t.Fatalf("unsafe quota accepted: %+v", mutated)
		}
	}
}
