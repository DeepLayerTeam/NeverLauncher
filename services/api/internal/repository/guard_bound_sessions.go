package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GuardBoundSession0507 contains only verified measurements and immutable account,
// server and build bindings. It contains neither an access token nor a device key.
type GuardBoundSession0507 struct {
	CorrelationID, JoinID, UserID, SessionID, MinecraftSessionID, TrustedDeviceID, DeviceKeyFingerprint string
	BindingEpoch                                                                                        int64
	ServerID, ProjectID, ProfileID, Channel, Username, PlayerUUID, IdentityRealm                        string
	PlanSHA256, CatalogSHA256, ReleaseSignature, GuardAttestationSHA256, GuardEvidenceSHA256            string
	GuardSHA256, LauncherSHA256, LauncherVersion, RuntimePolicySHA256                                   string
	ModuleSetSHA256, CodeSetSHA256, HookSetSHA256, JVMStateSHA256                                       string
	JavaMajor                                                                                           int
	GuardPID                                                                                            int64
	IssuedAt, LastCheckedAt                                                                             time.Time
	// Snapshot from the authoritative active player row, never from the node.
	LiveUserID, LiveSessionID, LiveMinecraftSessionID, LiveTrustedDeviceID string
	LiveBindingEpoch                                                       int64
	LiveProjectID, LiveProfileID, LiveChannel, LiveUsername, LiveUUID      string
}

// GuardBoundSessionStore0507 is intentionally only implemented by the durable
// PostgreSQL backend; memory/SQLite must not silently simulate protected joins.
type GuardBoundSessionStore0507 interface {
	SaveGuardBoundSession0507(context.Context, GuardBoundSession0507) error
	GetGuardBoundSession0507(context.Context, string) (GuardBoundSession0507, error)
	ListDueGuardBoundSessions0507(context.Context, string, time.Time, int) ([]GuardBoundSession0507, error)
	ListUnboundGuardPlayerSessions0507(context.Context, string, int) ([]string, error)
	MarkGuardBoundSessionChecked0507(context.Context, string, time.Time) error
	InvalidateGuardBoundSession0507(context.Context, string, string, time.Time) (bool, error)
}

const guardBoundColumns0507 = `correlation_id,join_id,user_id,session_id,minecraft_session_id,trusted_device_id,device_key_fingerprint,binding_epoch,server_id,project_id,profile_id,channel,username,player_uuid,identity_realm,plan_sha256,catalog_sha256,release_signature,guard_attestation_sha256,guard_evidence_sha256,guard_sha256,launcher_sha256,launcher_version,runtime_policy_sha256,module_set_sha256,code_set_sha256,hook_set_sha256,jvm_state_sha256,java_major,guard_pid,issued_at,last_checked_at`

func scanGuardBoundSession0507(row interface{ Scan(...any) error }) (GuardBoundSession0507, error) {
	var b GuardBoundSession0507
	var checked sql.NullTime
	err := row.Scan(&b.CorrelationID, &b.JoinID, &b.UserID, &b.SessionID, &b.MinecraftSessionID, &b.TrustedDeviceID, &b.DeviceKeyFingerprint, &b.BindingEpoch,
		&b.ServerID, &b.ProjectID, &b.ProfileID, &b.Channel, &b.Username, &b.PlayerUUID, &b.IdentityRealm,
		&b.PlanSHA256, &b.CatalogSHA256, &b.ReleaseSignature, &b.GuardAttestationSHA256, &b.GuardEvidenceSHA256,
		&b.GuardSHA256, &b.LauncherSHA256, &b.LauncherVersion, &b.RuntimePolicySHA256,
		&b.ModuleSetSHA256, &b.CodeSetSHA256, &b.HookSetSHA256, &b.JVMStateSHA256, &b.JavaMajor, &b.GuardPID, &b.IssuedAt, &checked)
	if checked.Valid {
		b.LastCheckedAt = checked.Time
	}
	return b, err
}

func scanDueGuardBoundSession0507(row interface{ Scan(...any) error }) (GuardBoundSession0507, error) {
	var b GuardBoundSession0507
	var checked sql.NullTime
	err := row.Scan(&b.CorrelationID, &b.JoinID, &b.UserID, &b.SessionID, &b.MinecraftSessionID, &b.TrustedDeviceID, &b.DeviceKeyFingerprint, &b.BindingEpoch,
		&b.ServerID, &b.ProjectID, &b.ProfileID, &b.Channel, &b.Username, &b.PlayerUUID, &b.IdentityRealm,
		&b.PlanSHA256, &b.CatalogSHA256, &b.ReleaseSignature, &b.GuardAttestationSHA256, &b.GuardEvidenceSHA256,
		&b.GuardSHA256, &b.LauncherSHA256, &b.LauncherVersion, &b.RuntimePolicySHA256,
		&b.ModuleSetSHA256, &b.CodeSetSHA256, &b.HookSetSHA256, &b.JVMStateSHA256, &b.JavaMajor, &b.GuardPID, &b.IssuedAt, &checked,
		&b.LiveUserID, &b.LiveSessionID, &b.LiveMinecraftSessionID, &b.LiveTrustedDeviceID, &b.LiveBindingEpoch, &b.LiveProjectID, &b.LiveProfileID, &b.LiveChannel, &b.LiveUsername, &b.LiveUUID)
	if checked.Valid {
		b.LastCheckedAt = checked.Time
	}
	return b, err
}

func (r *SQLRepository) SaveGuardBoundSession0507(ctx context.Context, b GuardBoundSession0507) error {
	if err := r.check(); err != nil {
		return err
	}
	if !validPlayerCorrelation0197(b.CorrelationID) || b.JoinID == "" || b.UserID == "" || b.SessionID == "" || b.TrustedDeviceID == "" || b.BindingEpoch < 1 || b.JavaMajor < 1 || b.GuardPID < 1 || b.IssuedAt.IsZero() {
		return fmt.Errorf("%w: invalid Guard session binding", ErrConflict)
	}
	// Insert-only. A reissued ticket cannot silently rewrite the original
	// signed plan or the account/device identity of a correlated session.
	_, err := r.db.ExecContext(ctx, `INSERT INTO server_bridge_guard_sessions_0507 (`+guardBoundColumns0507[:len(guardBoundColumns0507)-len(",last_checked_at")]+`) VALUES (`+placeholdersGuard0507()+`)`,
		b.CorrelationID, b.JoinID, b.UserID, b.SessionID, b.MinecraftSessionID, b.TrustedDeviceID, b.DeviceKeyFingerprint, b.BindingEpoch,
		b.ServerID, b.ProjectID, b.ProfileID, b.Channel, b.Username, b.PlayerUUID, b.IdentityRealm, b.PlanSHA256, b.CatalogSHA256, b.ReleaseSignature,
		b.GuardAttestationSHA256, b.GuardEvidenceSHA256, b.GuardSHA256, b.LauncherSHA256, b.LauncherVersion, b.RuntimePolicySHA256,
		b.ModuleSetSHA256, b.CodeSetSHA256, b.HookSetSHA256, b.JVMStateSHA256, b.JavaMajor, b.GuardPID, b.IssuedAt.UTC())
	return err
}

func placeholdersGuard0507() string {
	parts := make([]string, 31)
	for i := range parts {
		parts[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(parts, ",")
}

func (r *SQLRepository) GetGuardBoundSession0507(ctx context.Context, correlation string) (GuardBoundSession0507, error) {
	if err := r.check(); err != nil {
		return GuardBoundSession0507{}, err
	}
	return scanGuardBoundSession0507(r.db.QueryRowContext(ctx, `SELECT `+guardBoundColumns0507+` FROM server_bridge_guard_sessions_0507 WHERE correlation_id=$1`, correlation))
}

func (r *SQLRepository) ListDueGuardBoundSessions0507(ctx context.Context, node string, now time.Time, max int) ([]GuardBoundSession0507, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if max < 1 || max > 128 {
		return nil, fmt.Errorf("invalid Guard recheck batch size")
	}
	qualifiedColumns := "g." + strings.ReplaceAll(guardBoundColumns0507, ",", ",g.")
	rows, err := r.db.QueryContext(ctx, `SELECT `+qualifiedColumns+`,p.user_id,p.session_id,p.minecraft_session_id,p.trusted_device_id,p.binding_epoch,p.project_id,p.profile_id,p.channel,p.username,p.player_uuid FROM server_bridge_guard_sessions_0507 g JOIN server_bridge_player_sessions_v3 p USING(correlation_id)
        WHERE p.status='active' AND (p.proxy_node_id=$1 OR p.backend_node_id=$1)
        AND (g.last_checked_at IS NULL OR g.last_checked_at < $2 - interval '10 seconds')
        ORDER BY g.last_checked_at NULLS FIRST,g.correlation_id LIMIT $3`, node, now.UTC(), max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GuardBoundSession0507, 0, max)
	for rows.Next() {
		b, e := scanDueGuardBoundSession0507(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// A policy may be enabled while pre-0.50.7 players are already connected.
// Do not silently grandfather those sessions into a protected server.
func (r *SQLRepository) ListUnboundGuardPlayerSessions0507(ctx context.Context, node string, max int) ([]string, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if max < 1 || max > 128 {
		return nil, fmt.Errorf("invalid unbound player batch size")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT p.correlation_id FROM server_bridge_player_sessions_v3 p
        LEFT JOIN server_bridge_guard_sessions_0507 g ON g.correlation_id=p.correlation_id
        WHERE p.status='active' AND (p.proxy_node_id=$1 OR p.backend_node_id=$1) AND g.correlation_id IS NULL
        ORDER BY p.updated_at,p.correlation_id LIMIT $2`, node, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, max)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *SQLRepository) MarkGuardBoundSessionChecked0507(ctx context.Context, correlation string, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE server_bridge_guard_sessions_0507 SET last_checked_at=$2 WHERE correlation_id=$1 AND EXISTS(SELECT 1 FROM server_bridge_player_sessions_v3 p WHERE p.correlation_id=$1 AND p.status='active')`, correlation, now.UTC())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *SQLRepository) InvalidateGuardBoundSession0507(ctx context.Context, correlation, reason string, now time.Time) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	if !validPlayerCorrelation0197(correlation) || strings.TrimSpace(reason) == "" {
		return false, errors.New("invalid Guard revocation input")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	ok, err := r.invalidatePlayerSessionRowTx0197(ctx, tx, correlation, "guard:"+reason, now.UTC())
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return ok, nil
}
