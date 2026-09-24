package httpapi

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestServerBridgeHandoffID0148Uses192BitsOfCSPRNGMaterial(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		id, err := newServerBridgeHandoffID0148()
		if err != nil {
			t.Fatalf("new handoff id: %v", err)
		}
		if !strings.HasPrefix(id, "ho_") {
			t.Fatalf("unexpected handoff prefix: %q", id)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "ho_"))
		if err != nil || len(raw) != 24 {
			t.Fatalf("handoff id must encode 24 random bytes, len=%d err=%v", len(raw), err)
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate handoff id: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestBridgeProxyKind0148IsStrict(t *testing.T) {
	for _, kind := range []string{"velocity", "BungeeCord", " waterfall "} {
		if !bridgeProxyKind0148(kind) {
			t.Fatalf("expected proxy kind %q", kind)
		}
	}
	for _, kind := range []string{"paper", "fabric", "forge", "proxy", ""} {
		if bridgeProxyKind0148(kind) {
			t.Fatalf("unexpected proxy kind %q", kind)
		}
	}
}

func TestBridgeJoinFromHandoff0148PreservesTargetSecurityBinding(t *testing.T) {
	now := time.Now().UTC()
	h := model.ServerBridgeHandoff{ID: "ho_test", Username: "Player", UUID: "uuid", UserID: "user", SessionID: "session", TargetNodeID: "paper-1", ProjectID: "project", ProfileID: "profile", Channel: "stable", TrustedDeviceID: "device", BindingEpoch: 7, MinecraftSessionID: "mc", TargetIdentityEpoch: 4, TargetKeyFingerprint: strings.Repeat("a", 64), Status: "active", CreatedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	j := bridgeJoinFromHandoff0148(h)
	if j.ID != h.ID || j.ServerID != h.TargetNodeID || j.IssuedIdentityEpoch != h.TargetIdentityEpoch || j.IssuedKeyFingerprint != h.TargetKeyFingerprint || j.BindingEpoch != h.BindingEpoch || j.SessionID != h.SessionID {
		t.Fatalf("handoff mapping lost security binding: %#v", j)
	}
}
