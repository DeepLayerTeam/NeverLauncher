package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Включено в CI PostgreSQL с тем же DSN, что и набор проверок HA ServerBridge.
func TestServerBridgeControl0195Postgres(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("LAUNCHER_SERVERBRIDGE_HA_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("repository is not SQLRepository")
	}
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	projectID := "control0195-project"
	if _, err := repo.SaveProject(model.Project{ID: projectID, Name: "Control 0195", DefaultChannel: "stable"}); err != nil {
		t.Fatal(err)
	}
	_, _ = repo.db.ExecContext(ctx, `DELETE FROM server_bridge_nodes_v2 WHERE id='control0195-node'`)
	node := model.ServerBridgeNode{ID: "control0195-node", Name: "control0195-node", Kind: "paper", ProjectID: projectID, KeyAlgorithm: "ed25519", PublicKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", KeyFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", IdentityEpoch: 1, IdentityRotatedAt: now, Status: "active", ProtocolVersion: 3, CreatedAt: now}
	if _, err := repo.SaveServerBridgeNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	runtimeID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := repo.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET runtime_id=$2,runtime_epoch=11,runtime_last_seen_at=$3 WHERE id=$1`, node.ID, runtimeID, now); err != nil {
		t.Fatal(err)
	}

	cmd := model.ServerBridgeControlCommand{
		ID: "ctl_control0195", ServerID: node.ID, RuntimeEpoch: 11, RuntimeID: runtimeID,
		Type: "server.save", Payload: map[string]string{},
		PayloadSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		RequestedBy:   "admin@example.test", IdempotencyKey: "control0195-idem", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	created, reused, err := repo.CreateServerBridgeControlCommand(ctx, cmd, now)
	if err != nil || reused || created.ID != cmd.ID {
		t.Fatalf("create: %+v reused=%v err=%v", created, reused, err)
	}
	replayed, reused, err := repo.CreateServerBridgeControlCommand(ctx, cmd, now.Add(time.Millisecond))
	if err != nil || !reused || replayed.ID != cmd.ID {
		t.Fatalf("idempotent create: %+v reused=%v err=%v", replayed, reused, err)
	}
	conflict := cmd
	conflict.ID = "ctl_control0195_conflict"
	conflict.RequestDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, _, err := repo.CreateServerBridgeControlCommand(ctx, conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	if _, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0123456789abcdef0123456789abcdef", "lease_wrong_0123456789abcdef", 0, now, 30*time.Second); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong runtime lease should conflict, got %v", err)
	}
	leased, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, "0123456789abcdef0123456789abcdef", "lease_token_0123456789abcdef", 0, now, 30*time.Second)
	if err != nil || leased.Status != "leased" || leased.Attempt != 1 {
		t.Fatalf("lease: %+v err=%v", leased, err)
	}
	resumed, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, "0123456789abcdef0123456789abcdef", "ignored_token_0123456789abcdef", 0, now.Add(time.Second), 30*time.Second)
	if err != nil || resumed.ID != leased.ID || resumed.Attempt != leased.Attempt || resumed.LeaseToken != leased.LeaseToken {
		t.Fatalf("resumed lease mismatch: %+v err=%v", resumed, err)
	}
	if _, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, leased.LeaseOwner, "wrong_token_0123456789abcdef", leased.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale/wrong lease token was not fenced: %v", err)
	}
	done, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second))
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("complete: %+v err=%v", done, err)
	}
	done2, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(2*time.Second))
	if err != nil || done2.Status != "succeeded" {
		t.Fatalf("idempotent completion: %+v err=%v", done2, err)
	}
	if _, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "false"}, "", now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-status ACK with conflicting result accepted: %v", err)
	}
	if _, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "failed", nil, "late", now.Add(3*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting ACK accepted: %v", err)
	}
	var auditCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id IN ($1,$2)`, "serverbridge-control-queued-"+cmd.ID, "serverbridge-control-complete-"+cmd.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("expected queued+completed transactional audit rows, got %d", auditCount)
	}

	// В 0.51.5 две независимые реплики API могут обработать одну доставку даже при
	// шестичасовом расхождении времени на HTTP- или worker-хосте. Аренду и момент
	// безопасной сверки неподтверждённого побочного эффекта определяют часы БД.
	// Истёкшая доставка НИКОГДА не становится вторым выполнением.
	second, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("second repository is not SQLRepository")
	}
	defer second.db.Close()
	cmd2 := cmd
	cmd2.ID = "ctl_control0195_skew_0515"
	cmd2.IdempotencyKey = "control0195-skew-0515"
	cmd2.ExpiresAt = time.Now().UTC().Add(2 * time.Minute)
	cmd2.CreatedAt = time.Now().UTC()
	cmd2.UpdatedAt = cmd2.CreatedAt
	_, _, err = repo.CreateServerBridgeControlCommand(ctx, cmd2, time.Now().UTC().Add(6*time.Hour))
	if err != nil {
		t.Fatalf("fast API clock incorrectly rejected pending command: %v", err)
	}
	channel := "skew_channel_0123456789abcdef"
	token := "skew_token_0123456789abcdef"
	first, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, channel, token, 0, time.Now().UTC().Add(6*time.Hour), 30*time.Second)
	if err != nil || first.ID != cmd2.ID {
		t.Fatalf("fast clock expired pending command: %+v, %v", first, err)
	}
	var dbNow time.Time
	if err := repo.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		t.Fatal(err)
	}
	if delta := first.LeaseUntil.Sub(dbNow); delta < 20*time.Second || delta > 35*time.Second {
		t.Fatalf("lease must use database time, remaining: %v", delta)
	}
	resumedOtherReplica, err := second.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, channel, "new_token_0123456789abcdef", 0, time.Now().UTC().Add(-6*time.Hour), 30*time.Second)
	if err != nil || resumedOtherReplica.ID != first.ID || resumedOtherReplica.LeaseToken != token || resumedOtherReplica.Attempt != 1 {
		t.Fatalf("other API replica must resume original delivery, not reexecute: %+v, %v", resumedOtherReplica, err)
	}
	_, err = second.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, "other_channel_0123456789abcdef", "other_token_0123456789abcdef", 0, time.Now().UTC().Add(-6*time.Hour), 30*time.Second)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second channel claimed active delivery: %v", err)
	}
	doneSkew, err := second.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd2.ID, channel, token, first.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", time.Now().UTC().Add(-6*time.Hour))
	if err != nil || doneSkew.Status != "succeeded" {
		t.Fatalf("cross replica ACK failed: %+v, %v", doneSkew, err)
	}
	if delta := doneSkew.CompletedAt.Sub(dbNow); delta < -5*time.Second || delta > 10*time.Second {
		t.Fatalf("ACK evidence incorrectly uses an API host clock: %v", delta)
	}
	lateACK, err := repo.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd2.ID, channel, token, first.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", time.Now().UTC().Add(6*time.Hour))
	if err != nil || lateACK.Status != "succeeded" {
		t.Fatalf("lost ACK retry across replicas: %+v, %v", lateACK, err)
	}
	cmd3 := cmd2
	cmd3.ID = "ctl_control0195_expiry_0515"
	cmd3.IdempotencyKey = "control0195-expiry-0515"
	_, _, err = repo.CreateServerBridgeControlCommand(ctx, cmd3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := repo.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, channel, "expired_token_0123456789abcdef", first.DeliverySequence, time.Now().Add(-6*time.Hour), 30*time.Second)
	if err != nil || pending.ID != cmd3.ID {
		t.Fatalf("lease command 3: %+v, %v", pending, err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE server_bridge_control_commands_v3 SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, cmd3.ID); err != nil {
		t.Fatal(err)
	}
	_, err = second.LeaseServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, "other_channel_0123456789abcdef", "retry_token_0123456789abcdef", first.DeliverySequence, time.Now().Add(-6*time.Hour), 30*time.Second)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired side effect must never be redelivered: %v", err)
	}
	current, err := second.GetServerBridgeControlCommand(ctx, node.ID, cmd3.ID)
	if err != nil || current.Status != "indeterminate" {
		t.Fatalf("expired command not reconciled: %+v, %v", current, err)
	}
	resolved, err := second.CompleteServerBridgeControlCommand(ctx, node.ID, 11, runtimeID, cmd3.ID, channel, pending.LeaseToken, pending.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", time.Now().UTC().Add(6*time.Hour))
	if err != nil || resolved.Status != "succeeded" {
		t.Fatalf("original durable late ACK rejected: %+v, %v", resolved, err)
	}
}
