//go:build !launcher_nopgx

package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Проверяет настоящую схему PostgreSQL, активную привязку игрока и очередь
// связанных команд отключения ServerBridge. Mock-репозиториев в памяти
// недостаточно.
func TestServerBoundGuardPostgres0507(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("Ожидался репозиторий PostgreSQL")
	}
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user, project, node := "gb-user-"+suffix, "gb-project-"+suffix, "gb-node-"+suffix
	session, mcSession, device := "gb-session-"+suffix, "gb-mc-"+suffix, "gb-device-"+suffix
	correlation := fmt.Sprintf("%x", sha256.Sum256([]byte(suffix)))
	runtimeID := strings.Repeat("b", 64)
	uuid := "05070000-0000-4000-8000-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,email,display_name,role_id,status,password_hash) VALUES($1,$2,'Guard 0507','player','active','hash-before')`, []any{user, user + "@example.test"}},
		{`INSERT INTO projects(id,name) VALUES($1,'Guard Session 0507 Integration')`, []any{project}},
		{`INSERT INTO server_bridge_nodes_v2(id,name,project_id,token_hash,kind,runtime_id,runtime_epoch) VALUES($1,'Guard Session Proxy',$2,'','velocity',$3,1)`, []any{node, project, runtimeID}},
	} {
		if _, err := r.db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	// Триггер допуска БД проверяет действующий аутентифицированный родительский
	// сеанс. Создавайте пару отложенных внешних ключей auth-session/refresh-family
	// точно как при промышленном допуске; не обходите триггер ради теста.
	family := "gb-family-" + suffix
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour')`, session, user, user+"@example.test", family); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, family, session, user); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.ExecContext(ctx, `INSERT INTO server_bridge_player_sessions_v3(correlation_id,player_uuid,username,username_normalized,user_id,session_id,minecraft_session_id,trusted_device_id,binding_epoch,project_id,profile_id,channel,proxy_node_id,proxy_runtime_id,proxy_runtime_epoch) VALUES($1,$2,'GuardPlayer','guardplayer',$3,$4,$5,$6,3,$7,'fabric','stable',$8,$9,1)`, correlation, uuid, user, session, mcSession, device, project, node, runtimeID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, q := range []struct {
			sql string
			arg string
		}{
			{`DELETE FROM server_bridge_guard_sessions_0507 WHERE correlation_id=$1`, correlation},
			{`DELETE FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1`, correlation},
			{`DELETE FROM server_bridge_nodes_v2 WHERE id=$1`, node},
			{`DELETE FROM projects WHERE id=$1`, project},
			{`DELETE FROM users WHERE id=$1`, user},
		} {
			_, _ = r.db.ExecContext(cleanupCtx, q.sql, q.arg)
		}
	}()
	before, err := r.ListUnboundGuardPlayerSessions0507(ctx, node, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 || before[0] != correlation {
		t.Fatalf("missing pre-policy active session must be identified: %v", before)
	}
	hash := func(x string) string { return strings.Repeat(x, 64) }
	now := time.Now().UTC()
	bound := GuardBoundSession0507{
		CorrelationID: correlation, JoinID: "gb-ticket-" + suffix, UserID: user, SessionID: session,
		MinecraftSessionID: mcSession, TrustedDeviceID: device, DeviceKeyFingerprint: hash("a"), BindingEpoch: 3,
		ServerID: node, ProjectID: project, ProfileID: "fabric", Channel: "stable", Username: "GuardPlayer", PlayerUUID: uuid, IdentityRealm: "local",
		PlanSHA256: hash("1"), CatalogSHA256: hash("2"), ReleaseSignature: strings.Repeat("3", 128),
		GuardAttestationSHA256: hash("4"), GuardEvidenceSHA256: hash("5"), GuardSHA256: hash("6"), LauncherSHA256: hash("7"),
		LauncherVersion: "0.50.7", RuntimePolicySHA256: hash("8"), ModuleSetSHA256: hash("9"), CodeSetSHA256: hash("a"),
		HookSetSHA256: hash("b"), JVMStateSHA256: hash("c"), JavaMajor: 21, GuardPID: 507, IssuedAt: now,
	}
	if err := r.SaveGuardBoundSession0507(ctx, bound); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveGuardBoundSession0507(ctx, bound); err == nil {
		t.Fatal("replay may not replace immutable Guard binding")
	}
	stored, err := r.GetGuardBoundSession0507(ctx, correlation)
	if err != nil || stored.PlanSHA256 != bound.PlanSHA256 || stored.DeviceKeyFingerprint != bound.DeviceKeyFingerprint {
		t.Fatalf("stored binding mismatch: %+v, %v", stored, err)
	}
	after, err := r.ListUnboundGuardPlayerSessions0507(ctx, node, 32)
	if err != nil || len(after) != 0 {
		t.Fatalf("signed binding did not bind active player: %v / %v", after, err)
	}
	due, err := r.ListDueGuardBoundSessions0507(ctx, node, now, 32)
	if err != nil || len(due) != 1 {
		t.Fatalf("active player must be due: %+v / %v", due, err)
	}
	if due[0].LiveUserID != bound.UserID || due[0].LiveMinecraftSessionID != bound.MinecraftSessionID ||
		due[0].LiveTrustedDeviceID != bound.TrustedDeviceID || due[0].LiveBindingEpoch != 3 {
		t.Fatalf("live player authority mismatch: %+v", due[0])
	}
	if err := r.MarkGuardBoundSessionChecked0507(ctx, correlation, now); err != nil {
		t.Fatal(err)
	}
	due, err = r.ListDueGuardBoundSessions0507(ctx, node, now.Add(2*time.Second), 32)
	if err != nil || len(due) != 0 {
		t.Fatalf("recheck pacing failed: %v / %v", due, err)
	}
	due, err = r.ListDueGuardBoundSessions0507(ctx, node, now.Add(11*time.Second), 32)
	if err != nil || len(due) != 1 {
		t.Fatalf("overdue session must be rechecked: %v / %v", due, err)
	}
	revoked, err := r.InvalidateGuardBoundSession0507(ctx, correlation, "guard_build_revoked", now)
	if err != nil || !revoked {
		t.Fatalf("Guard revocation must invalidate player: %v / %v", revoked, err)
	}
	revoked, err = r.InvalidateGuardBoundSession0507(ctx, correlation, "repeat", now)
	if err != nil || revoked {
		t.Fatalf("Guard revocation must be idempotent: %v / %v", revoked, err)
	}
	var status, reason string
	if err := r.db.QueryRowContext(ctx, `SELECT status,invalidated_reason FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1`, correlation).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "invalidated" || !strings.Contains(reason, "guard_build_revoked") {
		t.Fatalf("Неожиданное состояние игровой сессии: %s %s", status, reason)
	}
	var kicked int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_control_commands_v3 WHERE payload->>'sessionCorrelationId'=$1 AND command_type='player.kick'`, correlation).Scan(&kicked); err != nil {
		t.Fatal(err)
	}
	if kicked != 1 {
		t.Fatalf("expected exactly one correlation-bound kick command, got %d", kicked)
	}
}
