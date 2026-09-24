package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// ServerBridgeRepository is implemented by the PostgreSQL repository and is the
// source of truth for ServerBridge Protocol v2. MemoryRepository intentionally
// does not implement it; dev/test therefore keeps the lightweight in-memory path.
type ServerBridgeRepository interface {
	SaveServerBridgeNode(context.Context, model.ServerBridgeNode) (model.ServerBridgeNode, error)
	GetServerBridgeNode(context.Context, string) (model.ServerBridgeNode, error)
	ListServerBridgeNodes(context.Context) ([]model.ServerBridgeNode, error)
	RotateServerBridgeNodeCredential(context.Context, string, string, string, time.Time) (model.ServerBridgeNode, error)
	SetServerBridgeNodeIntegrity(context.Context, string, string, string, string, time.Time) error
	TouchServerBridgeNodeHeartbeat(context.Context, string, string, string, time.Time) error
	CreateServerBridgeJoinTicket(context.Context, model.ServerBridgeJoinTicket) (model.ServerBridgeJoinTicket, error)
	GetActiveServerBridgeJoinTicket(context.Context, string, string, time.Time) (model.ServerBridgeJoinTicket, error)
	ConsumeServerBridgeJoinTicket(context.Context, string, time.Time) (model.ServerBridgeJoinTicket, error)
	InvalidateServerBridgeJoinTicket(context.Context, string, time.Time) (bool, error)
	InvalidateServerBridgeSession(context.Context, string, string, time.Time) (int, error)
	InvalidateServerBridgeUser(context.Context, string, time.Time) (int, error)
	SaveServerBridgeTexture(context.Context, model.ServerBridgeTexture) (model.ServerBridgeTexture, error)
	GetServerBridgeTexture(context.Context, string) (model.ServerBridgeTexture, error)
	ServerBridgeSummary(context.Context, time.Time) (map[string]any, error)
}

func scanServerBridgeNode(row interface{ Scan(...any) error }) (model.ServerBridgeNode, error) {
	var n model.ServerBridgeNode
	var verifiedAt, heartbeatAt, rotatedAt sql.NullTime
	err := row.Scan(&n.ID, &n.Name, &n.Kind, &n.ProjectID, &n.ProfileID, &n.Fingerprint, &n.TokenHash, &n.TokenPrefix, &n.Status, &n.ProtocolVersion, &n.PluginVersion, &n.PluginSHA256, &n.IntegrityStatus, &verifiedAt, &heartbeatAt, &n.CreatedAt, &rotatedAt)
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if verifiedAt.Valid {
		n.IntegrityVerifiedAt = verifiedAt.Time
	}
	if heartbeatAt.Valid {
		n.LastHeartbeatAt = heartbeatAt.Time
	}
	if rotatedAt.Valid {
		n.RotatedAt = rotatedAt.Time
	}
	return n, nil
}

const bridgeNodeSelectV2 = `SELECT id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,plugin_version,plugin_sha256,integrity_status,integrity_verified_at,last_heartbeat_at,created_at,rotated_at FROM server_bridge_nodes_v2`

func (r *SQLRepository) SaveServerBridgeNode(ctx context.Context, n model.ServerBridgeNode) (model.ServerBridgeNode, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	if n.ProtocolVersion == 0 {
		n.ProtocolVersion = 2
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1401, hashtext($1))`, n.ID); err != nil {
		return model.ServerBridgeNode{}, err
	}
	var previousHash string
	err = tx.QueryRowContext(ctx, `SELECT token_hash FROM server_bridge_nodes_v2 WHERE id=$1 FOR UPDATE`, n.ID).Scan(&previousHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeNode{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,status,protocol_version,plugin_version,plugin_sha256,integrity_status,integrity_verified_at,last_heartbeat_at,created_at,rotated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,kind=EXCLUDED.kind,project_id=EXCLUDED.project_id,profile_id=EXCLUDED.profile_id,fingerprint=EXCLUDED.fingerprint,token_hash=EXCLUDED.token_hash,token_prefix=EXCLUDED.token_prefix,status=EXCLUDED.status,protocol_version=2,plugin_version=EXCLUDED.plugin_version,plugin_sha256=EXCLUDED.plugin_sha256,integrity_status=EXCLUDED.integrity_status,integrity_verified_at=EXCLUDED.integrity_verified_at,last_heartbeat_at=EXCLUDED.last_heartbeat_at,rotated_at=EXCLUDED.rotated_at`,
		n.ID, n.Name, n.Kind, n.ProjectID, n.ProfileID, n.Fingerprint, n.TokenHash, n.TokenPrefix, n.Status, n.ProtocolVersion, n.PluginVersion, n.PluginSHA256, n.IntegrityStatus, timeArg(n.IntegrityVerifiedAt), timeArg(n.LastHeartbeatAt), n.CreatedAt, timeArg(n.RotatedAt))
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if previousHash != "" && previousHash != n.TokenHash {
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE server_id=$1 AND status='active'`, n.ID, time.Now().UTC()); err != nil {
			return model.ServerBridgeNode{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	return r.GetServerBridgeNode(ctx, n.ID)
}

func timeArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func (r *SQLRepository) GetServerBridgeNode(ctx context.Context, id string) (model.ServerBridgeNode, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	n, err := scanServerBridgeNode(r.db.QueryRowContext(ctx, bridgeNodeSelectV2+` WHERE id=$1`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeNode{}, ErrNotFound
	}
	return n, err
}

func (r *SQLRepository) ListServerBridgeNodes(ctx context.Context) ([]model.ServerBridgeNode, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, bridgeNodeSelectV2+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ServerBridgeNode{}
	for rows.Next() {
		n, err := scanServerBridgeNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (r *SQLRepository) RotateServerBridgeNodeCredential(ctx context.Context, id, tokenHash, tokenPrefix string, now time.Time) (model.ServerBridgeNode, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1401, hashtext($1))`, id); err != nil {
		return model.ServerBridgeNode{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET token_hash=$2,token_prefix=$3,rotated_at=$4,protocol_version=2,plugin_version='',plugin_sha256='',integrity_status='',integrity_verified_at=NULL,last_heartbeat_at=NULL WHERE id=$1`, id, tokenHash, tokenPrefix, now.UTC())
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return model.ServerBridgeNode{}, ErrNotFound
	}
	_, err = tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE server_id=$1 AND status='active'`, id, now.UTC())
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	return r.GetServerBridgeNode(ctx, id)
}

func (r *SQLRepository) SetServerBridgeNodeIntegrity(ctx context.Context, id, version, hash, status string, verifiedAt time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	var at any
	if !verifiedAt.IsZero() {
		at = verifiedAt.UTC()
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET plugin_version=$2,plugin_sha256=$3,integrity_status=$4,integrity_verified_at=$5 WHERE id=$1`, id, strings.TrimSpace(version), strings.ToLower(strings.TrimSpace(hash)), status, at)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SQLRepository) TouchServerBridgeNodeHeartbeat(ctx context.Context, id, kind, pluginVersion string, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET kind=CASE WHEN btrim($2)='' THEN kind ELSE lower(btrim($2)) END,status='active',fingerprint=CASE WHEN fingerprint='' AND btrim($3)<>'' THEN 'plugin:'||btrim($3) ELSE fingerprint END,last_heartbeat_at=$4 WHERE id=$1`, id, kind, pluginVersion, now.UTC())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanBridgeJoin(row interface{ Scan(...any) error }) (model.ServerBridgeJoinTicket, error) {
	var j model.ServerBridgeJoinTicket
	var consumed sql.NullTime
	err := row.Scan(&j.ID, &j.Username, &j.UsernameNormalized, &j.UUID, &j.UserID, &j.SessionID, &j.ServerID, &j.ProjectID, &j.ProfileID, &j.Channel, &j.AccessTokenHash, &j.TrustedDeviceID, &j.BindingEpoch, &j.MinecraftSessionID, &j.ProtocolVersion, &j.Status, &j.CreatedAt, &j.ExpiresAt, &consumed)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if consumed.Valid {
		j.ConsumedAt = consumed.Time
	}
	return j, nil
}

const bridgeJoinSelectV2 = `SELECT id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),protocol_version,status,created_at,expires_at,consumed_at FROM server_bridge_join_tickets_v2`

func (r *SQLRepository) CreateServerBridgeJoinTicket(ctx context.Context, j model.ServerBridgeJoinTicket) (model.ServerBridgeJoinTicket, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	j.Username = strings.TrimSpace(j.Username)
	j.UsernameNormalized = strings.ToLower(j.Username)
	j.ServerID = strings.TrimSpace(j.ServerID)
	j.ProjectID = strings.TrimSpace(j.ProjectID)
	j.ProfileID = strings.TrimSpace(j.ProfileID)
	if j.ProtocolVersion == 0 {
		j.ProtocolVersion = 2
	}
	if j.Status == "" {
		j.Status = "active"
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	defer tx.Rollback()
	joinLockKey := strings.TrimSpace(j.ServerID) + ":" + strings.ToLower(strings.TrimSpace(j.UsernameNormalized))
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1402, hashtext($1))`, joinLockKey); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	var status, projectID, profileID string
	err = tx.QueryRowContext(ctx, `SELECT status,project_id,profile_id FROM server_bridge_nodes_v2 WHERE id=$1 FOR SHARE`, j.ServerID).Scan(&status, &projectID, &profileID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeJoinTicket{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if status != "active" {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server bridge node is not active")
	}
	if projectID != "" && projectID != j.ProjectID {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server project binding mismatch")
	}
	if profileID != "" && profileID != j.ProfileID {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server profile binding mismatch")
	}
	_, err = tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='replaced',invalidated_at=$3 WHERE server_id=$1 AND username_normalized=$2 AND status='active'`, j.ServerID, j.UsernameNormalized, j.CreatedAt)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_join_tickets_v2(id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,trusted_device_id,binding_epoch,minecraft_session_id,protocol_version,status,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),$13,NULLIF($14,''),2,'active',$15,$16)`, j.ID, j.Username, j.UsernameNormalized, j.UUID, j.UserID, j.SessionID, j.ServerID, j.ProjectID, j.ProfileID, j.Channel, j.AccessTokenHash, j.TrustedDeviceID, j.BindingEpoch, j.MinecraftSessionID, j.CreatedAt.UTC(), j.ExpiresAt.UTC())
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	j.ProtocolVersion = 2
	j.Status = "active"
	return j, nil
}

func (r *SQLRepository) GetActiveServerBridgeJoinTicket(ctx context.Context, username, serverID string, now time.Time) (model.ServerBridgeJoinTicket, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	j, err := scanBridgeJoin(r.db.QueryRowContext(ctx, bridgeJoinSelectV2+` WHERE server_id=$1 AND username_normalized=$2 AND status='active' AND expires_at>$3 ORDER BY created_at DESC LIMIT 1`, strings.TrimSpace(serverID), strings.ToLower(strings.TrimSpace(username)), now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeJoinTicket{}, ErrNotFound
	}
	return j, err
}

func (r *SQLRepository) ConsumeServerBridgeJoinTicket(ctx context.Context, id string, now time.Time) (model.ServerBridgeJoinTicket, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	j, err := scanBridgeJoin(r.db.QueryRowContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='consumed',consumed_at=$2 WHERE id=$1 AND status='active' AND expires_at>$2 RETURNING id,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),protocol_version,status,created_at,expires_at,consumed_at`, id, now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeJoinTicket{}, ErrConflict
	}
	return j, err
}

func (r *SQLRepository) InvalidateServerBridgeJoinTicket(ctx context.Context, id string, now time.Time) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE id=$1 AND status='active'`, id, now.UTC())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
func (r *SQLRepository) InvalidateServerBridgeSession(ctx context.Context, sessionID, serverID string, now time.Time) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	q := `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$3 WHERE session_id=$1 AND ($2='' OR server_id=$2) AND status='active'`
	res, err := r.db.ExecContext(ctx, q, sessionID, serverID, now.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
func (r *SQLRepository) InvalidateServerBridgeUser(ctx context.Context, userID string, now time.Time) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE user_id=$1 AND status='active'`, userID, now.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *SQLRepository) SaveServerBridgeTexture(ctx context.Context, t model.ServerBridgeTexture) (model.ServerBridgeTexture, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeTexture{}, err
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO server_bridge_textures_v2(player_uuid,username,skin_url,cape_url,model,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(player_uuid) DO UPDATE SET username=EXCLUDED.username,skin_url=EXCLUDED.skin_url,cape_url=EXCLUDED.cape_url,model=EXCLUDED.model,updated_at=EXCLUDED.updated_at`, t.UUID, t.Username, t.SkinURL, t.CapeURL, t.Model, t.UpdatedAt.UTC())
	return t, err
}
func (r *SQLRepository) GetServerBridgeTexture(ctx context.Context, uuid string) (model.ServerBridgeTexture, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeTexture{}, err
	}
	var t model.ServerBridgeTexture
	err := r.db.QueryRowContext(ctx, `SELECT player_uuid,username,skin_url,cape_url,model,updated_at FROM server_bridge_textures_v2 WHERE player_uuid=$1`, uuid).Scan(&t.UUID, &t.Username, &t.SkinURL, &t.CapeURL, &t.Model, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeTexture{}, ErrNotFound
	}
	return t, err
}
func (r *SQLRepository) ServerBridgeSummary(ctx context.Context, now time.Time) (map[string]any, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var nodes, joins, textures int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_nodes_v2`).Scan(&nodes); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active' AND expires_at>$1`, now.UTC()).Scan(&joins); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_textures_v2`).Scan(&textures); err != nil {
		return nil, err
	}
	return map[string]any{"servers": nodes, "activeJoins": joins, "textures": textures, "joinTtlSeconds": 120, "serverToken": "required-for-validation", "protocolVersion": 2, "sourceOfTruth": "postgresql"}, nil
}
