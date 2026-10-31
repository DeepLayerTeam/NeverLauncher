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

// Exercises both connections: revocation is committed by one replica and the
// other must observe terminal Minecraft/bridge/work state without polling.
func TestGlobalSessionRevocationPostgres0297(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected postgres")
	}
	defer a.db.Close()
	b, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
	if !ok {
		t.Fatal("expected postgres")
	}
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := "revoke-0297-" + suffix
	first, second := "sess-a-"+suffix, "sess-b-"+suffix
	familyA, familyB := "family-a-"+suffix, "family-b-"+suffix
	mc := "mc-" + suffix
	player := fmt.Sprintf("%x", sha256.Sum256([]byte(suffix)))
	if _, err := a.db.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,password_hash) VALUES($1,$2,'Revocation Test','player','active','hash-before')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, user)
	uuid := "02970000-0000-4000-8000-" + fmt.Sprintf("%012d", time.Now().UnixNano()%1000000000000)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name) VALUES($1,$2,$3)`, user, uuid, "Revoke0297"); err != nil {
		t.Fatal(err)
	}
	for i, pair := range [][2]string{{first, familyA}, {second, familyB}} {
		// Auth session and its refresh family have a deferred bidirectional FK.
		tx, err := a.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,'player',$4,'active',now()+interval '1 hour')`, pair[0], user, user+"@example.test", pair[1]); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, pair[1], pair[0], user); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')`, "rt-"+pair[0], pair[1], pair[0], fmt.Sprintf("%064d", i+91)); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO minecraft_sessions(id,user_id,never_session_id,profile_uuid,access_token_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')`, mc, user, first, uuid, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO minecraft_joins(username,username_normalized,profile_uuid,user_id,minecraft_session_id,server_id,expires_at) VALUES('Revoke0297','revoke0297',$1,$2,$3,'test-bridge',now()+interval '1 minute')`, uuid, user, mc); err != nil {
		t.Fatal(err)
	}
	project := "project-" + suffix
	node := "node-" + suffix
	runtimeID := strings.Repeat("a", 64)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,'Revocation E2E')`, project); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO server_bridge_nodes_v2(id,name,project_id,token_hash,kind,runtime_id,runtime_epoch) VALUES($1,'Revocation Proxy',$2,'','velocity',$3,1)`, node, project, runtimeID); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM server_bridge_nodes_v2 WHERE id=$1`, node)
	if _, err := a.db.ExecContext(ctx, `INSERT INTO server_bridge_player_sessions_v3(correlation_id,player_uuid,username,username_normalized,user_id,never_session_id,binding_epoch,project_id,profile_id,channel,proxy_node_id,proxy_runtime_id,proxy_runtime_epoch) VALUES($1,$2,'Revoke0297','revoke0297',$3,$4,1,$5,'test-profile','stable',$6,$7,1)`, player, uuid, user, first, project, node, runtimeID); err != nil {
		t.Fatal(err)
	}
	job := "job-" + suffix
	if _, err := a.db.ExecContext(ctx, `INSERT INTO durable_jobs(id,kind,actor_type,actor_id,action,resource_type,resource_id,idempotency_key,payload,payload_digest,status,lease_owner,lease_token,lease_fence,lease_expires_at) VALUES($1,'test','user',$2,'release:publish','release','test-release',$3,'{}'::jsonb,$4,'running','worker','lease-token',1,now()+interval '1 minute')`, job, user, "idemp-"+suffix, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO durable_job_attempts(job_id,attempt,worker_id,lease_fence,status) VALUES($1,1,'worker',1,'running')`, job); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM durable_jobs WHERE id=$1`, job)
	defer a.db.ExecContext(context.Background(), `DELETE FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1`, player)

	if _, err := a.db.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason='test-logout' WHERE id=$1`, first); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		sql  string
		want string
	}{
		{`SELECT status FROM refresh_token_families WHERE id=$1`, "revoked"},
		{`SELECT status FROM minecraft_sessions WHERE id=$1`, "revoked"},
		{`SELECT status FROM server_bridge_player_sessions_v3 WHERE never_session_id=$1`, "invalidated"},
	} {
		key := first
		if strings.Contains(check.sql, "refresh_token_families") {
			key = familyA
		}
		if strings.Contains(check.sql, "minecraft_sessions") {
			key = mc
		}
		var got string
		if err := b.db.QueryRowContext(ctx, check.sql, key).Scan(&got); err != nil || got != check.want {
			t.Fatalf("%s: got %q, err %v", check.sql, got, err)
		}
	}
	var joins int
	if err := b.db.QueryRowContext(ctx, `SELECT count(*) FROM minecraft_joins WHERE minecraft_session_id=$1`, mc).Scan(&joins); err != nil || joins != 0 {
		t.Fatalf("join not invalidated: %d %v", joins, err)
	}
	var kicks int
	if err := b.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_control_commands_v3 WHERE server_id=$1 AND command_type='player.kick' AND status='pending' AND requested_by='serverbridge-player-session'`, node).Scan(&kicks); err != nil || kicks != 1 {
		t.Fatalf("online player was not scheduled for disconnection: %d %v", kicks, err)
	}
	// Even the second API connection must be unable to issue a Minecraft token
	// against a revoked parent, independent of replica-local caches.
	if _, err := b.db.ExecContext(ctx, `INSERT INTO minecraft_sessions(id,user_id,never_session_id,profile_uuid,access_token_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')`, "late-"+suffix, user, first, uuid, strings.Repeat("d", 64)); err == nil {
		t.Fatal("concurrent-revocation gate allowed new Minecraft authorization")
	}
	var status string
	if err := b.db.QueryRowContext(ctx, `SELECT status FROM durable_jobs WHERE id=$1`, job).Scan(&status); err != nil || status != "running" {
		t.Fatalf("other active session should preserve job: %q %v", status, err)
	}
	// A sensitive user change revokes all remaining sessions through the DB trigger.
	if _, err := b.db.ExecContext(ctx, `UPDATE users SET role_id='viewer' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT status FROM auth_sessions WHERE id=$1`, `SELECT status FROM refresh_token_families WHERE session_id=$1`} {
		if err := a.db.QueryRowContext(ctx, q, second).Scan(&status); err != nil || status != "revoked" {
			t.Fatalf("role revocation: %s: %q %v", q, status, err)
		}
	}
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM durable_jobs WHERE id=$1`, job).Scan(&status); err != nil || status != "revoked" {
		t.Fatalf("job not fenced: %q %v", status, err)
	}
	// Revoked session IDs are permanently terminal.
	if _, err := a.db.ExecContext(ctx, `UPDATE auth_sessions SET status='active',revoked_at=NULL,revoked_reason='' WHERE id=$1`, second); err == nil {
		t.Fatal("a revoked session was resurrected")
	}
	// Updating an unrelated user field must not log out a new session.
	fresh := "new-" + suffix
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,'viewer',$4,'active',now()+interval '1 hour')`, fresh, user, user+"@example.test", "fresh-family-"+suffix); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, "fresh-family-"+suffix, fresh, user); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE users SET display_name='Renamed' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if err := b.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, fresh).Scan(&status); err != nil || status != "active" {
		t.Fatalf("profile update incorrectly revoked session: %q %v", status, err)
	}
	// Editing role permissions is a live security change even if users.role_id
	// and users.project_roles remain identical. It must reject cached tokens.
	role := "role-0297-" + suffix
	if _, err := a.db.ExecContext(ctx, `INSERT INTO roles(id,name,permissions) VALUES($1,'Role Revocation Test','["project:read"]'::jsonb)`, role); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM roles WHERE id=$1`, role)
	if _, err := b.db.ExecContext(ctx, `UPDATE users SET role_id=$2 WHERE id=$1`, user, role); err != nil {
		t.Fatal(err)
	}
	roleSession := "role-session-" + suffix
	roleFamily := "role-family-" + suffix
	tx, err = a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,refresh_family_id,status,expires_at) VALUES($1,$2,$3,$4,$5,'active',now()+interval '1 hour')`, roleSession, user, user+"@example.test", role, roleFamily); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id) VALUES($1,$2,$3)`, roleFamily, roleSession, user); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.ExecContext(ctx, `UPDATE roles SET permissions='[]'::jsonb WHERE id=$1`, role); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, roleSession).Scan(&status); err != nil || status != "revoked" {
		t.Fatalf("role permission edit retained access: %q %v", status, err)
	}
}
