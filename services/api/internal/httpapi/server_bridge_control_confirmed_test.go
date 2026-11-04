package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestBridgeOutcomeClassification0411(t *testing.T) {
	cases := []struct {
		name, kind, ack, expected string
		request, result           map[string]string
	}{
		{"accepted shutdown", "server.shutdown", "accepted", "accepted", nil, map[string]string{"scheduled": "true"}},
		{"legacy shutdown no success", "server.shutdown", "succeeded", "accepted", nil, map[string]string{"scheduled": "true"}},
		{"legacy save", "server.save", "succeeded", "executed", nil, map[string]string{"saved": "true"}},
		{"legacy generic console", "server.console", "succeeded", "executed", nil, map[string]string{"accepted": "true"}},
		{"observed maintenance", "server.maintenance", "succeeded", "succeeded", map[string]string{"enabled": "true"}, map[string]string{"enabled": "true", "mode": "maintenance", "verification": "platform-state-read"}},
		{"different observed value", "server.maintenance", "succeeded", "executed", map[string]string{"enabled": "true"}, map[string]string{"enabled": "false", "mode": "maintenance", "verification": "platform-state-read"}},
		{"wrong mode", "server.drain", "succeeded", "executed", map[string]string{"enabled": "false"}, map[string]string{"enabled": "false", "mode": "maintenance", "verification": "platform-state-read"}},
		{"not actually verified", "server.drain", "succeeded", "executed", map[string]string{"enabled": "false"}, map[string]string{"enabled": "false", "mode": "drain"}},
		{"whitelist readback", "whitelist.add", "succeeded", "succeeded", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "whitelisted": "true", "verification": "platform-state-read"}},
		{"unrelated whitelist player", "whitelist.add", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Alex", "whitelisted": "true", "verification": "platform-state-read"}},
		{"whitelist disabled", "whitelist.disable", "succeeded", "succeeded", nil, map[string]string{"enabled": "false", "verification": "platform-state-read"}},
		{"ban added with readback", "ban.add", "succeeded", "succeeded", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "banned": "true", "verification": "platform-state-read"}},
		{"ban remove with readback", "ban.remove", "succeeded", "succeeded", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "banned": "false", "verification": "platform-state-read"}},
		{"ban different player", "ban.add", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Alex", "banned": "true", "verification": "platform-state-read"}},
		{"ban no readback", "ban.add", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "banned": "true"}},
		{"kick observed quit", "player.kick", "succeeded", "succeeded", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "uuid": "3a0da4ae-9ca9-4d3f-bb84-e5a5c8abe833", "online": "false", "verification": "player-quit-event"}},
		{"kick mismatched player", "player.kick", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Alex", "uuid": "3a0da4ae-9ca9-4d3f-bb84-e5a5c8abe833", "online": "false", "verification": "player-quit-event"}},
		{"kick no event", "player.kick", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "online": "false", "verification": "platform-state-read"}},
		{"kick no uuid", "player.kick", "succeeded", "executed", map[string]string{"username": "Steve"}, map[string]string{"username": "Steve", "online": "false", "verification": "player-quit-event"}},
		{"unsupported invented verification", "server.console", "succeeded", "executed", nil, map[string]string{"verification": "platform-state-read"}},
		{"handler invoked", "player.kick", "executed", "executed", nil, nil},
		{"failed remains failed", "server.shutdown", "failed", "failed", nil, nil},
		{"uncertain remains uncertain", "server.shutdown", "indeterminate", "indeterminate", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := model.ServerBridgeControlCommand{Type: c.kind, Payload: c.request}
			if got := classifyBridgeControlOutcome0411(cmd, c.ack, c.result); got != c.expected {
				t.Fatalf("got %s, want %s", got, c.expected)
			}
		})
	}
}
