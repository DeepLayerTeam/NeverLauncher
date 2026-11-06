package extensionhost

import (
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestJavaBridgeControlValidation0488(t *testing.T) {
	for _, tc := range []struct {
		kind    string
		payload map[string]string
		allowed bool
	}{
		{"message.broadcast", map[string]string{"message": "hello"}, true},
		{"player.kick", map[string]string{"username": "player1", "reason": "test"}, true},
		{"server.save", map[string]string{}, true},
		{"server.maintenance", map[string]string{"enabled": "false"}, true},
		{"server.drain", map[string]string{"enabled": "true"}, true},
		{"server.console", map[string]string{"command": "op player1"}, false},
		{"server.shutdown", map[string]string{}, false},
		{"message.broadcast", map[string]string{"command": "op player1"}, false},
		{"message.broadcast", map[string]string{}, false},
		{"server.save", map[string]string{"unexpected": "value"}, false},
		{"server.maintenance", map[string]string{"enabled": "maybe"}, false},
		{"player.kick", map[string]string{"username": "p\nfoo"}, false},
	} {
		_, err := bridgePayload0488(tc.kind, tc.payload)
		if (err == nil) != tc.allowed {
			t.Errorf("%s %+v expected allowed=%v got %v", tc.kind, tc.payload, tc.allowed, err)
		}
	}
}
func TestJavaBridgeRuntimeFencing0488(t *testing.T) {
	now := time.Now().UTC()
	runtime := strings.Repeat("a", 64)
	n := model.ServerBridgeNode{ID: "node", ProjectID: "p", Status: "active", Kind: "paper", ServerBrand: "Paper", ProtocolVersion: 3,
		RuntimeEpoch: 2, RuntimeID: runtime, RuntimeLastSeenAt: now.Add(-time.Second), RuntimeCapabilities: []string{"adapter.control.broadcast", "adapter.control.save"}, IntegrityStatus: "verified"}
	if !bridgeRuntimeControl0488(n, "server.save", now) {
		t.Fatal("verified current Paper adapter must accept save")
	}
	for name, mutate := range map[string]func(*model.ServerBridgeNode){
		"unverified":         func(v *model.ServerBridgeNode) { v.IntegrityStatus = "rejected" },
		"stale":              func(v *model.ServerBridgeNode) { v.RuntimeLastSeenAt = now.Add(-100 * time.Second) },
		"offline":            func(v *model.ServerBridgeNode) { v.Status = "inactive" },
		"epoch":              func(v *model.ServerBridgeNode) { v.RuntimeEpoch = 0 },
		"bad runtime":        func(v *model.ServerBridgeNode) { v.RuntimeID = "invalid" },
		"unsupported cap":    func(v *model.ServerBridgeNode) { v.RuntimeCapabilities = nil },
		"untrusted platform": func(v *model.ServerBridgeNode) { v.Kind = "unknown" },
		"hybrid":             func(v *model.ServerBridgeNode) { v.ServerBrand = "Arclight" },
		"proxy save":         func(v *model.ServerBridgeNode) { v.Kind = "velocity" },
	} {
		v := n
		mutate(&v)
		if bridgeRuntimeControl0488(v, "server.save", now) {
			t.Errorf("admitted: %s", name)
		}
	}
	if bridgeRuntimeControl0488(n, "server.console", now) {
		t.Fatal("console is not available to extensions")
	}
}
func TestJavaBridgeResponseRedaction0488(t *testing.T) {
	n := model.ServerBridgeNode{ID: "s1", ProjectID: "p1", TokenHash: "token", PublicKey: "public", KeyFingerprint: "fingerprint", PluginSHA256: "secret"}
	out := bridgeNodeView0488(n)
	for _, secret := range []string{"tokenHash", "publicKey", "keyFingerprint", "pluginSha256", "identityDigest"} {
		if _, ok := out[secret]; ok {
			t.Fatalf("Произошла утечка учётных данных узла: %s", secret)
		}
	}
	cmd := model.ServerBridgeControlCommand{ID: "c1", ServerID: "s1", Type: "message.broadcast", Payload: map[string]string{"message": "private"}, LeaseToken: "lease-secret", RequestedBy: "actor"}
	view := bridgeCommandView0488(cmd)
	for _, secret := range []string{"payload", "leaseToken", "requestedBy", "runtimeId", "requestDigest"} {
		if _, ok := view[secret]; ok {
			t.Fatalf("command credential leaked: %s", secret)
		}
	}
	if len(out) == 0 || len(view) == 0 {
		t.Fatal("status view empty")
	}
}
