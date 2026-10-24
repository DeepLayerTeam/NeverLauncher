package httpapi

import (
	"strings"
	"testing"
	"time"
)

func TestAdapterCapabilities0286RejectOverclaimAndHybrid(t *testing.T) {
	cases := []struct {
		platform string
		brand    string
		caps     []string
		good     bool
	}{
		{"paper", "Paper", []string{"adapter.universal-v1", "adapter.role.backend", "adapter.family.bukkit", "adapter.auth.login-gate", "adapter.control.save"}, true},
		{"vanilla", "Vanilla", []string{"adapter.universal-v1", "adapter.sidecar.rcon", "adapter.control.save"}, true},
		{"vanilla", "Vanilla", []string{"adapter.auth.login-gate"}, false},
		{"sponge", "Sponge", []string{"adapter.control.save"}, false},
		{"sponge", "Sponge", []string{"adapter.control.ban"}, false},
		{"sponge", "Sponge", []string{"adapter.control.console"}, false},
		{"velocity", "Velocity", []string{"adapter.control.whitelist"}, false},
		{"folia", "Folia", []string{"adapter.scheduler.region-safe"}, true},
		{"paper", "Paper", []string{"adapter.scheduler.region-safe"}, false},
		{"paper", "Mohist 1.21", nil, false},
		{"fabric", "Fabric", []string{"adapter.family.bukkit"}, false},
		{"paper", "Paper", []string{"adapter.control.root"}, false},
	}
	for _, tc := range cases {
		err := verifyAdapterCapabilities0286(tc.platform, tc.brand, tc.caps)
		if (err == nil) != tc.good {
			t.Errorf("%s %v: err=%v want good=%v", tc.platform, tc.caps, err, tc.good)
		}
	}
}

func TestAdapterCommandGate0286FailsClosed(t *testing.T) {
	node := bridgeServerRecord{Kind: "sponge", ServerBrand: "Sponge", RuntimeID: strings.Repeat("a", 64), RuntimeEpoch: 2,
		RuntimeLastSeenAt: time.Now(), RuntimeCapabilities: []string{"adapter.control.broadcast", "adapter.control.kick"}}
	if !serverBridgeNodeAllowsControl0286(node, "message.broadcast") {
		t.Fatal("advertised broadcast rejected")
	}
	for _, cmd := range []string{"server.save", "server.shell", "server.console", "whitelist.add"} {
		if serverBridgeNodeAllowsControl0286(node, cmd) {
			t.Errorf("unsupported operation permitted: %s", cmd)
		}
	}
	node.RuntimeLastSeenAt = time.Now().Add(-3 * time.Minute)
	if serverBridgeNodeAllowsControl0286(node, "message.broadcast") {
		t.Fatal("stale runtime allowed")
	}
	node.RuntimeLastSeenAt = time.Now()
	node.RuntimeCapabilities = nil
	if serverBridgeNodeAllowsControl0286(node, "message.broadcast") {
		t.Fatal("missing capability allowed")
	}
	node.Kind = "vanilla"
	node.RuntimeCapabilities = []string{"adapter.auth.login-gate", "adapter.control.broadcast"}
	if serverBridgeNodeAllowsControl0286(node, "message.broadcast") {
		t.Fatal("invalid signed capability set allowed")
	}
}
