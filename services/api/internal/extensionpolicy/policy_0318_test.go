package extensionpolicy

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/windowssandbox"
	"runtime"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func signedPolicy0318() model.ExtensionManifest {
	return model.ExtensionManifest{
		ID: "example.extension", Version: "1.1.0", Permissions: []string{"project:read"},
		Sandbox: &model.ExtensionSandboxPolicy{Version: "1", Mode: "isolated", FilesystemRead: []string{"package"}, FilesystemWrite: []string{"scratch"}, NetworkOutbound: []string{"example.com:443"}, Secrets: []string{"api_token"}, MaxProcesses: 2, MaxMemoryBytes: 64 << 20, MaxCPUPercent: 25, TimeoutSeconds: 30},
	}
}
func TestSignedPolicy0318NormalizeAndReject(t *testing.T) {
	base := signedPolicy0318()
	if _, err := Validate(base.Sandbox); err != nil {
		t.Fatal(err)
	}
	for name, modify := range map[string]func(*model.ExtensionSandboxPolicy){
		"unknown isolation":       func(p *model.ExtensionSandboxPolicy) { p.Mode = "disabled" },
		"missing memory boundary": func(p *model.ExtensionSandboxPolicy) { p.MaxMemoryBytes = 0 },
		"filesystem traversal":    func(p *model.ExtensionSandboxPolicy) { p.FilesystemWrite = []string{"../../etc"} },
		"write package":           func(p *model.ExtensionSandboxPolicy) { p.FilesystemWrite = []string{"package"} },
		"network wildcard":        func(p *model.ExtensionSandboxPolicy) { p.NetworkOutbound = []string{"*:443"} },
		"network malformed":       func(p *model.ExtensionSandboxPolicy) { p.NetworkOutbound = []string{"example.com:https"} },
		"network traversal":       func(p *model.ExtensionSandboxPolicy) { p.NetworkOutbound = []string{"../etc:443"} },
		"secret path":             func(p *model.ExtensionSandboxPolicy) { p.Secrets = []string{"../secret"} },
		"duplicate":               func(p *model.ExtensionSandboxPolicy) { p.Secrets = []string{"token", "token"} },
		"unbounded cpu":           func(p *model.ExtensionSandboxPolicy) { p.MaxCPUPercent = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			p := *base.Sandbox
			modify(&p)
			if _, err := Validate(&p); err == nil {
				t.Fatalf("invalid policy accepted: %+v", p)
			}
		})
	}
}
func TestSignedPolicy0318FailClosedRuntime(t *testing.T) {
	if err := LaunchAllowed(signedPolicy0318()); runtime.GOOS == "windows" && windowssandbox.Available() == nil {
		if err != nil {
			t.Fatalf("Windows AppContainer preflight refused: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "sandbox-unavailable") {
		t.Fatalf("isolated policy accepted without sandbox capability: %v", err)
	}
	legacy := signedPolicy0318()
	legacy.Sandbox = nil
	if err := LaunchAllowed(legacy); err != nil {
		t.Fatal(err)
	}
	trusted := signedPolicy0318()
	trusted.Sandbox.Mode = "trusted"
	if err := LaunchAllowed(trusted); err != nil {
		t.Fatal(err)
	}
}
func TestSignedPolicy0318OwnerReview(t *testing.T) {
	old := signedPolicy0318()
	old.Version = "1.0.0"
	old.Sandbox = nil
	updated := signedPolicy0318()
	changed, err := ChangesRequireApproval(old, updated)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if err := RequireReview(old, updated, ""); err == nil {
		t.Fatal("unattended update accepted")
	}
	digest, err := ApprovalDigest(updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireReview(old, updated, digest); err != nil {
		t.Fatal(err)
	}
	tampered := updated
	tampered.Permissions = []string{"project:read", "secrets:read"}
	if err := RequireReview(old, tampered, digest); err == nil {
		t.Fatal("digest reused after privilege escalation")
	}
	changed, err = ChangesRequireApproval(updated, updated)
	if err != nil || changed {
		t.Fatal("unchanged policy incorrectly needs review")
	}
	if err := RequireReview(updated, updated, ""); err != nil {
		t.Fatal(err)
	}
	narrower := updated
	copyPolicy := *updated.Sandbox
	narrower.Sandbox = &copyPolicy
	narrower.Sandbox.FilesystemWrite = nil
	if err := RequireReview(updated, narrower, ""); err == nil {
		t.Fatal("silent mode narrowing accepted")
	}
}
func TestSignedPolicy0318DigestBoundToExtensionAndVersion(t *testing.T) {
	a := signedPolicy0318()
	digest, _ := ApprovalDigest(a)
	a.ID = "other.extension"
	different, _ := ApprovalDigest(a)
	if digest == different {
		t.Fatal("unbound to ID")
	}
	a = signedPolicy0318()
	a.Version = "1.1.1"
	different, _ = ApprovalDigest(a)
	if digest == different {
		t.Fatal("unbound to version")
	}
}
