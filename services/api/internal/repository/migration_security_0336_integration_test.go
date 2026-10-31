//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcredentials"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Exercises the PostgreSQL revocation CASCADE from 0.29.7, checkpointed
// receipts, preview rollback, re-enrollment and exact replay (not mocks).
func TestMigrationSecurityTrustResetPostgres0336(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := "security336-" + suffix
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); err != nil {
		t.Fatal(err)
	}
	run, err := repo.CreateMigration0331(ctx, project, "gravit", "security-reset-0336-key")
	if err != nil {
		t.Fatal(err)
	}
	acc := gi.Account{Provider: "sql", SourceID: "security-" + suffix, Username: "Sec336", UUID: "e3544d61-8877-4a33-a234-" + fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff), SourcePath: "sql-export/users.csv"}
	userID := migratedUserID0335(acc)
	defer func() {
		c := context.Background()
		for _, q := range []string{
			`DELETE FROM device_challenges WHERE user_id=$1`, `DELETE FROM device_measured_boot_0315 WHERE user_id=$1`, `DELETE FROM device_hardware_evidence_0312 WHERE user_id=$1`,
			`DELETE FROM auth_sessions WHERE user_id=$1`, `DELETE FROM trusted_devices WHERE user_id=$1`,
		} {
			_, _ = repo.db.ExecContext(c, q, userID)
		}
		for _, table := range []string{"migration_security_resets_0336", "migration_security_targets_0336", "migration_auth_imports_0335", "migration_identity_rows_0334", "migration_identity_snapshots_0334", "migration_source_inventory_0333", "migration_compatibility_0332", "migration_events_0331"} {
			_, _ = repo.db.ExecContext(c, `DELETE FROM `+table+` WHERE run_id=$1`, run.ID)
		}
		_, _ = repo.db.ExecContext(c, `DELETE FROM migration_runs_0331 WHERE id=$1`, run.ID)
		_, _ = repo.db.ExecContext(c, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = repo.db.ExecContext(c, `DELETE FROM projects WHERE id=$1`, project)
	}()
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "worker-0336", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	source := inventoryFixture0333(t, "security336-source")
	if _, err = repo.SaveMigrationInventory0333(ctx, run.ID, source); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{acc}); err != nil {
		t.Fatal(err)
	}
	encoded, err := fileauth.EncodeCredential("sha256-hex", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	credential := gc.Credential{Account: acc, PasswordHash: encoded, Algorithm: "sha256-hex", State: "importable"}
	if _, err = repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", []gc.Credential{credential}, false); err != nil {
		t.Fatal(err)
	}
	sid := "trust-session-" + suffix
	did := "trust-device-" + suffix
	// Create a real previously trusted Never device and Never session; reset
	// must revoke both and any dependent families/refresh tokens.
	_, err = repo.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,assurance,key_algorithm,public_key,key_fingerprint) VALUES($1,$2,'pre-migration','active','verified','proof-of-possession','ed25519','test-public-key',$3)`, did, userID, fmt.Sprintf("%064x", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.db.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,email,role_id,device_id,device,status,refresh_family_id,expires_at) VALUES($1,$2,$3,'player',$4,'pre-migration','active',$5,now()+interval '2 hours')`, sid, userID, "Sec336@fileauth.invalid", did, "fam-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.db.ExecContext(ctx, `INSERT INTO refresh_token_families(id,session_id,user_id,status) VALUES($1,$2,$3,'active')`, "fam-"+suffix, sid, userID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.db.ExecContext(ctx, `INSERT INTO refresh_tokens(id,family_id,session_id,token_hash,status,expires_at) VALUES($1,$2,$3,$4,'current',now()+interval '2 hours')`, "rt-"+suffix, "fam-"+suffix, sid, "hash-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	kid, manifestHash := "new-kid-0336", strings.Repeat("b", 64)
	preview, err := repo.ResetMigrationTrust0336(ctx, run.ID, kid, manifestHash, true)
	if err != nil || preview.ImportedAccounts != 1 || preview.AppliedAt != nil {
		t.Fatalf("preview %#v %v", preview, err)
	}
	var state string
	if err = repo.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id=$1`, sid).Scan(&state); err != nil || state != "active" {
		t.Fatalf("preview changed session %s %v", state, err)
	}
	report, err := repo.ResetMigrationTrust0336(ctx, run.ID, kid, manifestHash, false)
	if err != nil || report.AppliedAt == nil || report.SessionsRevoked != 1 || report.DevicesRevoked != 1 {
		t.Fatalf("reset %#v %v", report, err)
	}
	for _, q := range []string{`SELECT status FROM auth_sessions WHERE id=$1`, `SELECT status FROM refresh_token_families WHERE session_id=$1`} {
		if err = repo.db.QueryRowContext(ctx, q, sid).Scan(&state); err != nil || state != "revoked" {
			t.Fatalf("dependent not revoked %s %v", state, err)
		}
	}
	if err = repo.db.QueryRowContext(ctx, `SELECT status FROM trusted_devices WHERE id=$1`, did).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("device not revoked: %s %v", state, err)
	}
	if _, err = repo.ResetMigrationTrust0336(ctx, run.ID, "different-kid", manifestHash, false); !errors.Is(err, mw.ErrConflict) {
		t.Fatalf("changed signer accepted %v", err)
	}
	// A new, independent key enrolled after reset is Never-owned and must not
	// be revoked by a repeated request after an uncertain response.
	newDevice := "new-device-" + suffix
	_, err = repo.db.ExecContext(ctx, `INSERT INTO trusted_devices(id,user_id,name,status,trust_state,assurance,key_algorithm,public_key,key_fingerprint) VALUES($1,$2,'fresh enrollment','active','verified','proof-of-possession','ed25519','new-public-key',$3)`, newDevice, userID, fmt.Sprintf("%064x", time.Now().UnixNano()+1))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := repo.ResetMigrationTrust0336(ctx, run.ID, kid, manifestHash, false)
	if err != nil || !replay.Verified || replay.DevicesRevoked != 1 {
		t.Fatalf("not idempotent %#v %v", replay, err)
	}
	if err = repo.db.QueryRowContext(ctx, `SELECT status FROM trusted_devices WHERE id=$1`, newDevice).Scan(&state); err != nil || state != "active" {
		t.Fatalf("replay revoked fresh device %s %v", state, err)
	}
	if _, err = repo.GetMigrationSecurity0336(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
}
