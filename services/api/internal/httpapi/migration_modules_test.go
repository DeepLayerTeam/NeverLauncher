package httpapi

import (
	"strings"
	"testing"
	"time"
)

func TestMigrationBridgeLive0446(t *testing.T) {
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	node := bridgeServerRecord{
		ID: "migrated-paper", ProjectID: "project1", ProfileID: "profile1", KeyAlgorithm: "ed25519", KeyFingerprint: strings.Repeat("a", 64),
		IdentityEpoch: 1, IdentityRotatedAt: now.Add(-time.Hour), Status: "active", RuntimeID: "new-runtime", RuntimeEpoch: 1,
		RuntimeIdentityDigest: strings.Repeat("b", 64), LastHeartbeatAt: now.Add(-5 * time.Second), RuntimeLastSeenAt: now.Add(-5 * time.Second),
	}
	tests := []struct {
		name   string
		change func(*bridgeServerRecord)
		state  string
	}{
		{"signed live node", func(*bridgeServerRecord) {}, "online"},
		{"stolen profile", func(n *bridgeServerRecord) { n.ProfileID = "other" }, "blocked"},
		{"replaced public key", func(n *bridgeServerRecord) { n.KeyFingerprint = strings.Repeat("c", 64) }, "blocked"},
		{"disabled", func(n *bridgeServerRecord) { n.Status = "disabled" }, "blocked"},
		{"unobserved runtime", func(n *bridgeServerRecord) { n.RuntimeID = "" }, "awaiting_runtime"},
		{"stale heartbeat", func(n *bridgeServerRecord) { n.LastHeartbeatAt = now.Add(-3 * time.Minute) }, "awaiting_runtime"},
		{"stale runtime", func(n *bridgeServerRecord) { n.RuntimeLastSeenAt = now.Add(-3 * time.Minute) }, "awaiting_runtime"},
		{"future heartbeat", func(n *bridgeServerRecord) { n.LastHeartbeatAt = now.Add(time.Minute) }, "awaiting_runtime"},
		{"old identity heartbeat", func(n *bridgeServerRecord) { n.IdentityRotatedAt = now.Add(-time.Second * 1) }, "awaiting_runtime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := node
			tt.change(&v)
			state, _ := migrationBridgeLive0446(v, "project1", "profile1", strings.Repeat("a", 64), now)
			if state != tt.state {
				t.Fatalf("got %q want %q", state, tt.state)
			}
		})
	}
}

func TestMigrationEnrollmentJSONStrict0446(t *testing.T) {
	good := `{"wrapperPath":"wrapper.json","id":"node1","profileId":"profile1","publicKey":"key","kind":"paper"}`
	var req moduleEnrollmentRequest0338
	if err := decodeMigrationEnrollment0446(strings.NewReader(good), &req); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{good + ` {}`, `{"unknown":"value"}`, `null`, `{"wrapperPath":"x"} {}`} {
		if err := decodeMigrationEnrollment0446(strings.NewReader(bad), &req); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
