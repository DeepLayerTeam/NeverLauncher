package httpapi

import (
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestGameControlLostACKIsIndeterminateAndNeverRedispatched0285(t *testing.T) {
	now := time.Now().UTC()
	runtimeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{}, controlIdempotency: map[string]string{}}
	cmd := model.ServerBridgeControlCommand{
		ID: "ctl_lost_ack", ServerID: "survival", RuntimeEpoch: 3, RuntimeID: runtimeID,
		Type: "server.save", Payload: map[string]string{}, PayloadSHA256: "sha",
		RequestDigest: "original", RequestedBy: "operator", IdempotencyKey: "lost-ack-0285",
		Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	if _, _, err := store.createControl0195(cmd, now); err != nil {
		t.Fatal(err)
	}
	lease, err := store.leaseControl0195("survival", 3, runtimeID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "first_lease_1234567890123456", 0, now, 10*time.Second)
	if err != nil || lease.Status != "leased" {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	// Same channel reconnecting before expiry resumes the *same* delivery,
	// never allocates a second lease/fencing identity.
	resume, err := store.leaseControl0195("survival", 3, runtimeID, lease.LeaseOwner, "other_lease_1234567890123456", 0, now.Add(2*time.Second), 10*time.Second)
	if err != nil || resume.LeaseToken != lease.LeaseToken || resume.Attempt != 1 {
		t.Fatalf("resume=%+v err=%v", resume, err)
	}
	// The original game process might have executed the save, even though ACK
	// disappeared. A different channel MUST NOT obtain a second execution.
	_, err = store.leaseControl0195("survival", 3, runtimeID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "second_lease_1234567890123456", 0, now.Add(11*time.Second), 10*time.Second)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expired delivery was redelivered: %v", err)
	}
	original := store.controlCommands[cmd.ID]
	if original.Status != "indeterminate" || original.LeaseOwner != lease.LeaseOwner || original.LeaseToken != lease.LeaseToken || original.Attempt != 1 || original.CompletedAt.IsZero() {
		t.Fatalf("lost ACK not reconciled safely: %+v", original)
	}
	if _, err = store.completeControl0195("survival", 3, runtimeID, lease.ID, lease.LeaseOwner, lease.LeaseToken, lease.DeliverySequence, "succeeded", map[string]string{}, "", now.Add(12*time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("stale ACK overwrote uncertainty: %v", err)
	}
	repeat := cmd
	repeat.ID = "ctl_replay_different_id"
	stored, reused, err := store.createControl0195(repeat, now.Add(15*time.Second))
	if err != nil || !reused || stored.ID != cmd.ID || stored.Status != "indeterminate" {
		t.Fatalf("idem replay=%+v reused=%v err=%v", stored, reused, err)
	}
}

func TestGameControlPendingExpiresWithoutExecution0285(t *testing.T) {
	now := time.Now().UTC()
	runtimeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{}}
	store.controlCommands["pending"] = model.ServerBridgeControlCommand{ID: "pending", ServerID: "survival", RuntimeID: runtimeID, RuntimeEpoch: 1, Status: "pending", ExpiresAt: now.Add(-time.Second)}
	if _, err := store.leaseControl0195("survival", 1, runtimeID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "new_token_1234567890123456", 0, now, 30*time.Second); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expired pending command delivered: %v", err)
	}
	if got := store.controlCommands["pending"]; got.Status != "expired" || got.Attempt != 0 {
		t.Fatalf("wrong pre-dispatch expiry: %+v", got)
	}
}

func TestServerBridgeSignedDeliveryExpiresWithLease0285(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	command := model.ServerBridgeControlCommand{ExpiresAt: now.Add(5 * time.Minute), LeaseUntil: now.Add(15 * time.Second)}
	if expiry := controlWireExpiry0285(command); expiry != now.Add(15*time.Second).UnixMilli() {
		t.Fatalf("signed token outlives lease: %d", expiry)
	}
	command.ExpiresAt = now.Add(3 * time.Second)
	if expiry := controlWireExpiry0285(command); expiry != now.Add(3*time.Second).UnixMilli() {
		t.Fatalf("signed token outlives command: %d", expiry)
	}
	command.LeaseUntil = time.Time{}
	if expiry := controlWireExpiry0285(command); expiry != 0 {
		t.Fatalf("missing lease permitted: %d", expiry)
	}
}

func TestGameControlOldRuntimeCannotRetainLease0285(t *testing.T) {
	now := time.Now().UTC()
	oldID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	store := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{}}
	store.controlCommands["old"] = model.ServerBridgeControlCommand{ID: "old", ServerID: "survival", RuntimeID: oldID, RuntimeEpoch: 3, DeliverySequence: 1, Status: "leased", LeaseOwner: "old-channel-012345678901", LeaseToken: "old-lease-01234567890123456", LeaseUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, err := store.leaseControl0195("survival", 4, newID, "new-channel-012345678901", "new-lease-01234567890123456", 0, now, 30*time.Second); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("old runtime delivered into new epoch: %v", err)
	}
	if c := store.controlCommands["old"]; c.Status != "indeterminate" || c.LeaseToken != "old-lease-01234567890123456" {
		t.Fatalf("old runtime not fenced: %+v", c)
	}
}
