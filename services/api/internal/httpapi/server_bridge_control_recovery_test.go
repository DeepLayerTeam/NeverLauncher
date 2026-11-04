package httpapi

import (
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestServerBridgeLateReceipt0412(t *testing.T) {
	now := time.Now().UTC()
	const server, command, runtime, owner, lease = "node", "operation", "runtime", "0123456789abcdef0123456789abcdef", "lease-0123456789abcdef"
	original := model.ServerBridgeControlCommand{ID: command, ServerID: server, RuntimeEpoch: 3, RuntimeID: runtime,
		Type: "server.maintenance", Status: "leased", DeliverySequence: 1, LeaseOwner: owner, LeaseToken: lease,
		LeaseUntil: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	b := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{command: original}}
	old, err := b.getControl0195(server, command)
	if err != nil || old.Status != "indeterminate" {
		t.Fatalf("lease must expire without redelivery: %+v %v", old, err)
	}
	if _, err = b.completeControl0195(server, 3, runtime, command, owner, "different-token", 1,
		"succeeded", map[string]string{"verification": "platform-state-read"}, "", now); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("different token must fail, got %v", err)
	}
	proof := map[string]string{"verification": "platform-state-read", "enabled": "true"}
	saved, err := b.completeControl0195(server, 3, runtime, command, owner, lease, 1, "succeeded", proof, "", now)
	if err != nil || saved.Status != "succeeded" || saved.Attempt != original.Attempt {
		t.Fatalf("durable late proof must recover result without issuing another lease: %+v %v", saved, err)
	}
	replay, err := b.completeControl0195(server, 3, runtime, command, owner, lease, 1, "succeeded", proof, "", now.Add(time.Second))
	if err != nil || replay.Status != "succeeded" {
		t.Fatalf("identical ACK retry must be idempotent: %v", err)
	}
	if _, err = b.completeControl0195(server, 3, runtime, command, owner, lease, 1,
		"failed", nil, "", now); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("conflicting ACK must be refused, got %v", err)
	}
	if _, err = b.leaseControl0195(server, 3, runtime, owner, "another-lease-token", 0, now, time.Minute); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("completed command must not be redelivered, got %v", err)
	}
}

func TestServerBridgeAgentIndeterminateIsImmutable0412(t *testing.T) {
	now := time.Now().UTC()
	c := model.ServerBridgeControlCommand{ID: "op", ServerID: "srv", RuntimeEpoch: 3, RuntimeID: "runtime",
		Status: "indeterminate", Error: "executor threw after admission", DeliverySequence: 1,
		LeaseOwner: "channel0123456789abcdef", LeaseToken: "lease0123456789abcdef"}
	b := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{"op": c}}
	if _, err := b.completeControl0195("srv", 3, "runtime", "op", c.LeaseOwner, c.LeaseToken, 1,
		"succeeded", nil, "", now); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("actual unknown execution must remain immutable: %v", err)
	}
}
