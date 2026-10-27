package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gc "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcredentials"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

// MigrationSecurityReport0336 deliberately contains no user credentials, old
// trust material, access tokens, device public keys or authentication secrets.
type MigrationSecurityReport0336 struct {
	Format                      string     `json:"format"`
	RunID                       string     `json:"runId"`
	ImportedAccounts            int        `json:"importedAccounts"`
	ExistingNeverUntouched      int        `json:"existingNeverUntouched"`
	ManualResets                int        `json:"manualResets"`
	SessionsRevoked             int64      `json:"sessionsRevoked"`
	DevicesRevoked              int64      `json:"devicesRevoked"`
	ChallengesConsumed          int64      `json:"challengesConsumed"`
	HardwareEvidenceDeleted     int64      `json:"hardwareEvidenceDeleted"`
	MeasuredBootEvidenceDeleted int64      `json:"measuredBootEvidenceDeleted"`
	ActiveJWTKID                string     `json:"activeJwtKid"`
	ManifestPublicSHA256        string     `json:"manifestPublicSha256"`
	AppliedAt                   *time.Time `json:"appliedAt,omitempty"`
	Verified                    bool       `json:"verified"`
	ReadyForCutover             bool       `json:"readyForCutover"` // Always false until staged cutover certification.
	RequiresLogin               bool       `json:"requiresLogin"`
	RequiresDeviceEnrollment    bool       `json:"requiresDeviceEnrollment"`
	RequiresGuardAttestation    bool       `json:"requiresGuardAttestation"`
}

type migrationSecurityTarget0336 struct{ UserID, Name, UUID string }

// Deterministically derives affected targets from the *committed* MIG05 receipt,
// never from a client-supplied username or request body. Existing Never users are
// expressly excluded; their sessions/keys are Never-owned and are not Gravit trust.
func migrationSecurityTargets0336(rows []gc.Row) ([]migrationSecurityTarget0336, error) {
	out := make([]migrationSecurityTarget0336, 0, len(rows))
	seen := make(map[string]bool)
	for _, row := range rows {
		if row.State != "imported" {
			continue
		}
		if row.Provider != "sql" && row.Provider != "fileauth" {
			return nil, mw.ErrConflict
		}
		if row.SourceID == "" || row.Username == "" || row.UUID == "" {
			return nil, mw.ErrConflict
		}
		id := migratedUserID0335FromRow(row)
		if seen[id] {
			return nil, mw.ErrConflict
		}
		seen[id] = true
		out = append(out, migrationSecurityTarget0336{UserID: id, Name: row.Username, UUID: row.UUID})
	}
	return out, nil
}
func migratedUserID0335FromRow(row gc.Row) string {
	if row.Provider == "fileauth" {
		return "gravit-fileauth-" + strings.ReplaceAll(row.UUID, "-", "")
	}
	// Use exactly the existing MIG05 derivation, not a second UUID mapping.
	return migratedUserID0335FromSQL(row.SourceID)
}

// migrationSecurityTargets0336 expects the same stable user key that MIG05 used.
// This function lives here because identity source IDs must never be exposed in
// the security report or passed as request arguments.
func migratedUserID0335FromSQL(sourceID string) string {
	sum := sha256.Sum256([]byte("sql\x00" + sourceID))
	return "gravit-sql-" + hex.EncodeToString(sum[:16])
}

func securityAffected0336(res sql.Result) (int64, error) { return res.RowsAffected() }

// ResetMigrationTrust0336 does real durable revocation, in a single transaction
// with receipt and workflow event. Failed statements rollback all effects.
// Previews execute *the same validations and locks*, then rollback changes.
func (r *SQLRepository) ResetMigrationTrust0336(ctx context.Context, runID, kid, manifestPublicSHA string, preview bool) (MigrationSecurityReport0336, error) {
	var report MigrationSecurityReport0336
	if err := r.check(); err != nil {
		return report, err
	}
	if runID == "" || len(kid) > 96 || len(kid) < 1 || len(manifestPublicSHA) != 64 {
		return report, errors.New("invalid signer identification")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var status, step, kind string
	err = tx.QueryRowContext(ctx, `SELECT status,step,source_kind FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&status, &step, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return report, mw.ErrNotFound
	}
	if err != nil {
		return report, err
	}
	if status != "prepared" || step != "source_assessment" || kind != "gravit" {
		return report, mw.ErrBusy
	}
	var sourceHash, identityHash, authDigest string
	var authJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT source_sha256,identity_sha256,decision_sha256,report FROM migration_auth_imports_0335 WHERE run_id=$1`, runID).Scan(&sourceHash, &identityHash, &authDigest, &authJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return report, mw.ErrConflict
	}
	if err != nil {
		return report, err
	}
	var auth gc.Result
	if err = json.Unmarshal(authJSON, &auth); err != nil {
		return report, err
	}
	if auth.RunID != runID || auth.SourceSHA256 != sourceHash || auth.IdentitySHA256 != identityHash {
		return report, mw.ErrConflict
	}
	targets, err := migrationSecurityTargets0336(auth.Rows)
	if err != nil {
		return report, err
	}
	if len(targets) != auth.Imported || len(targets) == 0 {
		return report, mw.ErrConflict
	}
	if auth.Imported+auth.ExistingUnchanged+auth.ManualReset != len(auth.Rows) {
		return report, mw.ErrConflict
	}
	var blocked int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_identity_rows_0334 WHERE run_id=$1 AND status='blocked'`, runID).Scan(&blocked)
	if err != nil {
		return report, err
	}
	if blocked > 0 {
		return report, mw.ErrConflict
	}
	// A replay must never issue another destructive reset (including after a
	// player has enrolled a fresh Never device). Verify the signer and receipt.
	var raw []byte
	var oldDigest, oldKID, oldPublic string
	err = tx.QueryRowContext(ctx, `SELECT report,auth_decision_sha256,active_jwt_kid,manifest_public_sha256 FROM migration_security_resets_0336 WHERE run_id=$1`, runID).Scan(&raw, &oldDigest, &oldKID, &oldPublic)
	if err == nil {
		if oldDigest != authDigest || oldKID != kid || oldPublic != manifestPublicSHA {
			return report, mw.ErrConflict
		}
		if err = json.Unmarshal(raw, &report); err != nil {
			return report, err
		}
		if err = verifyReset0336(ctx, tx, runID, report); err != nil {
			return MigrationSecurityReport0336{}, err
		}
		report.Verified = true
		return report, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return report, err
	}
	report = MigrationSecurityReport0336{Format: "never/migration-security/v1", RunID: runID, ImportedAccounts: len(targets), ExistingNeverUntouched: auth.ExistingUnchanged, ManualResets: auth.ManualReset, ActiveJWTKID: kid, ManifestPublicSHA256: manifestPublicSHA, RequiresLogin: true, RequiresDeviceEnrollment: true, RequiresGuardAttestation: true}
	// Store target identities in the SAME transaction. Preview rolls them back.
	for start := 0; start < len(targets); start += 200 {
		end := start + 200
		if end > len(targets) {
			end = len(targets)
		}
		var q strings.Builder
		q.WriteString(`INSERT INTO migration_security_targets_0336(run_id,user_id,expected_name,expected_uuid) VALUES `)
		args := make([]any, 0, (end-start)*4)
		for i := start; i < end; i++ {
			if i > start {
				q.WriteByte(',')
			}
			fmt.Fprintf(&q, "($%d,$%d,$%d,$%d)", len(args)+1, len(args)+2, len(args)+3, len(args)+4)
			args = append(args, runID, targets[i].UserID, targets[i].Name, targets[i].UUID)
		}
		if _, err = tx.ExecContext(ctx, q.String(), args...); err != nil {
			return report, err
		}
	}
	// Lock the target user rows in stable order. The user FKs in session/device
	// registration take KEY SHARE locks, so concurrent enrollment cannot pass
	// through the cutover while these locks are held.
	locked, err := tx.QueryContext(ctx, `SELECT u.id FROM users u JOIN migration_security_targets_0336 t ON t.user_id=u.id AND t.run_id=$1 ORDER BY u.id FOR UPDATE OF u`, runID)
	if err != nil {
		return report, err
	}
	seen := 0
	for locked.Next() {
		var id string
		if err = locked.Scan(&id); err != nil {
			locked.Close()
			return report, err
		}
		seen++
	}
	err = locked.Err()
	locked.Close()
	if err != nil {
		return report, err
	}
	if seen != len(targets) {
		return report, mw.ErrConflict
	}
	var valid int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_security_targets_0336 t JOIN users u ON u.id=t.user_id JOIN minecraft_profiles p ON p.user_id=u.id WHERE t.run_id=$1 AND u.role_id='player' AND u.status='active' AND p.uuid=t.expected_uuid AND p.name=t.expected_name AND p.identity_version='gravit-import-v1'`, runID).Scan(&valid)
	if err != nil {
		return report, err
	}
	if valid != len(targets) {
		return report, mw.ErrConflict
	}
	if preview {
		return report, nil
	}
	// Use DB clock *after* user row locks, not transaction start time.
	var stamp time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&stamp); err != nil {
		return report, err
	}
	// The 0.29.7 session revocation trigger invalidates refresh families,
	// Minecraft/Yggdrasil sessions, joins, ServerBridge tickets and transfers.
	var n sql.Result
	n, err = tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=$2,revoked_reason='gravit-security-migration-0336' WHERE status='active' AND user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1)`, runID, stamp)
	if err != nil {
		return report, err
	}
	report.SessionsRevoked, err = securityAffected0336(n)
	if err != nil {
		return report, err
	}
	n, err = tx.ExecContext(ctx, `UPDATE device_challenges SET consumed_at=$2 WHERE consumed_at IS NULL AND user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1)`, runID, stamp)
	if err != nil {
		return report, err
	}
	report.ChallengesConsumed, err = securityAffected0336(n)
	if err != nil {
		return report, err
	}
	n, err = tx.ExecContext(ctx, `DELETE FROM device_hardware_evidence_0312 WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1)`, runID)
	if err != nil {
		return report, err
	}
	report.HardwareEvidenceDeleted, err = securityAffected0336(n)
	if err != nil {
		return report, err
	}
	n, err = tx.ExecContext(ctx, `DELETE FROM device_measured_boot_0315 WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1)`, runID)
	if err != nil {
		return report, err
	}
	report.MeasuredBootEvidenceDeleted, err = securityAffected0336(n)
	if err != nil {
		return report, err
	}
	n, err = tx.ExecContext(ctx, `UPDATE trusted_devices SET status='revoked',trust_state='revoked',assurance='proof-of-possession',attestation_state='revoked',attestation_method='',attested_at=NULL,attestation_expires_at=NULL,revoked_at=$2,revoked_reason='gravit-security-migration-0336',updated_at=$2 WHERE status='active' AND user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1)`, runID, stamp)
	if err != nil {
		return report, err
	}
	report.DevicesRevoked, err = securityAffected0336(n)
	if err != nil {
		return report, err
	}
	report.AppliedAt = &stamp
	raw, err = json.Marshal(report)
	if err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO migration_security_resets_0336(run_id,auth_decision_sha256,active_jwt_kid,manifest_public_sha256,report,applied_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, runID, authDigest, kid, manifestPublicSHA, string(raw), stamp); err != nil {
		return report, err
	}
	var rev int64
	err = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, runID).Scan(&rev)
	if err != nil {
		return report, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_security_reset','source_assessment',$2,jsonb_build_object('users',$3::int,'sessionsRevoked',$4::bigint,'devicesRevoked',$5::bigint,'challengesConsumed',$6::bigint))`, runID, rev, len(targets), report.SessionsRevoked, report.DevicesRevoked, report.ChallengesConsumed)
	if err != nil {
		return report, err
	}
	if err = tx.Commit(); err != nil {
		return report, fmt.Errorf("security reset commit uncertain; query receipt before any retry: %w", err)
	}
	return report, nil
}

// Revalidation checks actual post-cutover state: fresh logins/enrollments
// created *after* the reset are allowed, earlier trust must remain revoked.
func verifyReset0336(ctx context.Context, tx *sql.Tx, runID string, report MigrationSecurityReport0336) error {
	if report.AppliedAt == nil {
		return mw.ErrConflict
	}
	var affected int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM migration_security_targets_0336 WHERE run_id=$1`, runID).Scan(&affected)
	if err != nil {
		return err
	}
	if affected != report.ImportedAccounts {
		return mw.ErrConflict
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM auth_sessions WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1) AND status='active' AND created_at<$2`,
		`SELECT COUNT(*) FROM trusted_devices WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1) AND status='active' AND created_at<$2`,
		`SELECT COUNT(*) FROM device_challenges WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1) AND consumed_at IS NULL AND created_at<$2`,
		`SELECT COUNT(*) FROM device_hardware_evidence_0312 WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1) AND verified_at<$2`,
		`SELECT COUNT(*) FROM device_measured_boot_0315 WHERE user_id IN (SELECT user_id FROM migration_security_targets_0336 WHERE run_id=$1) AND verified_at<$2`,
	} {
		var remaining int
		if err = tx.QueryRowContext(ctx, query, runID, *report.AppliedAt).Scan(&remaining); err != nil {
			return err
		}
		if remaining != 0 {
			return mw.ErrConflict
		}
	}
	return nil
}

func (r *SQLRepository) GetMigrationSecurity0336(ctx context.Context, runID string) (MigrationSecurityReport0336, error) {
	var report MigrationSecurityReport0336
	if err := r.check(); err != nil {
		return report, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT report FROM migration_security_resets_0336 WHERE run_id=$1`, runID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return report, mw.ErrNotFound
	}
	if err != nil {
		return report, err
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		return report, err
	}
	if err = verifyReset0336(ctx, tx, runID, report); err != nil {
		return MigrationSecurityReport0336{}, err
	}
	if err = tx.Commit(); err != nil {
		return MigrationSecurityReport0336{}, err
	}
	report.Verified = true
	return report, nil
}
