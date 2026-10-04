package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// ServerBridgeRepository is implemented by the PostgreSQL repository and is the
// source of truth for ServerBridge Protocol v2/v3 rolling upgrades. MemoryRepository intentionally
// does not implement it; dev/test therefore keeps the lightweight in-memory path.
type ServerBridgeRepository interface {
	SaveServerBridgeNode(context.Context, model.ServerBridgeNode) (model.ServerBridgeNode, error)
	GetServerBridgeNode(context.Context, string) (model.ServerBridgeNode, error)
	ListServerBridgeNodes(context.Context) ([]model.ServerBridgeNode, error)
	RotateServerBridgeNodeIdentity(context.Context, string, string, string, string, time.Time) (model.ServerBridgeNode, error)
	ConsumeServerBridgeNodeNonce(context.Context, string, string, int64, time.Time, time.Time) (bool, error)
	SetServerBridgeNodeIntegrity(context.Context, string, string, string, string, time.Time) error
	TouchServerBridgeNodeHeartbeat(context.Context, string, string, string, int, time.Time) error
	TouchServerBridgeNodeRuntimeHeartbeat(context.Context, string, string, string, int, model.ServerBridgeRuntimeIdentity, time.Time) (model.ServerBridgeRuntimeTransition, error)
	SaveServerBridgeTelemetry(context.Context, string, int64, model.ServerBridgeTelemetry, time.Time) error
	SaveServerBridgeRoutingState(context.Context, string, int64, model.ServerBridgeRoutingSnapshot, time.Time) (model.ServerBridgeRoutingSnapshot, error)
	ListServerBridgeAllowedBackends(context.Context, string, time.Time) ([]model.ServerBridgeRouteTarget, error)
	EnsureServerBridgeNodeRoutable(context.Context, string, int64, string, time.Time) error
	AppendServerBridgeEvents(context.Context, string, int64, string, []model.ServerBridgeEvent, time.Time) (model.ServerBridgeEventAppendResult, error)
	CreateServerBridgeControlCommand(context.Context, model.ServerBridgeControlCommand, time.Time) (model.ServerBridgeControlCommand, bool, error)
	LeaseServerBridgeControlCommand(context.Context, string, int64, string, string, string, int64, time.Time, time.Duration) (model.ServerBridgeControlCommand, error)
	CompleteServerBridgeControlCommand(context.Context, string, int64, string, string, string, string, int64, string, map[string]string, string, time.Time) (model.ServerBridgeControlCommand, error)
	GetServerBridgeControlCommand(context.Context, string, string) (model.ServerBridgeControlCommand, error)
	CreateServerBridgeJoinTicket(context.Context, model.ServerBridgeJoinTicket) (model.ServerBridgeJoinTicket, error)
	GetActiveServerBridgeJoinTicket(context.Context, string, string, time.Time) (model.ServerBridgeJoinTicket, error)
	ConsumeServerBridgeJoinTicket(context.Context, string, model.ServerBridgeJoinRedemption, time.Time) (model.ServerBridgeJoinTicket, error)
	CreateServerBridgeHandoff(context.Context, model.ServerBridgeHandoff, time.Time) (model.ServerBridgeHandoff, error)
	GetActiveServerBridgeHandoff(context.Context, string, string, time.Time) (model.ServerBridgeHandoff, error)
	ConsumeServerBridgeHandoff(context.Context, string, model.ServerBridgeJoinRedemption, time.Time) (model.ServerBridgeHandoff, error)
	InvalidateServerBridgeHandoff(context.Context, string, time.Time) (bool, error)
	ListServerBridgeTopology(context.Context) ([]model.ServerBridgeTopologyEdge, error)
	MaintainServerBridge(context.Context, time.Time) (model.ServerBridgeMaintenanceResult, error)
	ServerBridgeHAStatus(context.Context, time.Time) (model.ServerBridgeHAStatus, error)
	InvalidateServerBridgeJoinTicket(context.Context, string, time.Time) (bool, error)
	InvalidateServerBridgeSession(context.Context, string, string, time.Time) (int, error)
	InvalidateServerBridgeUser(context.Context, string, time.Time) (int, error)
	SaveServerBridgeTexture(context.Context, model.ServerBridgeTexture) (model.ServerBridgeTexture, error)
	GetServerBridgeTexture(context.Context, string) (model.ServerBridgeTexture, error)
	ServerBridgeSummary(context.Context, time.Time) (map[string]any, error)
}

func scanServerBridgeNode(row interface{ Scan(...any) error }) (model.ServerBridgeNode, error) {
	var n model.ServerBridgeNode
	var verifiedAt, heartbeatAt, rotatedAt, identityRotatedAt sql.NullTime
	var runtimeStartedAt, runtimeFirstSeenAt, runtimeLastSeenAt sql.NullTime
	var runtimeCapabilities []byte
	var telemetryLatest []byte
	err := row.Scan(
		&n.ID, &n.Name, &n.Kind, &n.ProjectID, &n.ProfileID, &n.Fingerprint, &n.TokenHash, &n.TokenPrefix,
		&n.KeyAlgorithm, &n.PublicKey, &n.KeyFingerprint, &n.IdentityEpoch, &identityRotatedAt, &n.Status,
		&n.ProtocolVersion, &n.PluginVersion, &n.PluginSHA256, &n.IntegrityStatus, &verifiedAt, &heartbeatAt,
		&n.CreatedAt, &rotatedAt,
		&n.RuntimeID, &n.RuntimeEpoch, &n.RuntimePreviousID, &n.RuntimeTransition, &n.RuntimeReplacementDetected,
		&runtimeStartedAt, &runtimeFirstSeenAt, &runtimeLastSeenAt, &n.RuntimeUptimeSeconds, &n.RuntimeProcessID,
		&n.Hostname, &n.NodeName, &n.MinecraftVersion, &n.JavaVersion, &n.JavaVendor, &n.JavaVMName,
		&n.RuntimePlatform, &n.LoaderName, &n.LoaderVersion, &n.ServerBrand, &runtimeCapabilities, &n.RuntimeIdentityDigest, &telemetryLatest,
	)
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if identityRotatedAt.Valid {
		n.IdentityRotatedAt = identityRotatedAt.Time
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
	if runtimeStartedAt.Valid {
		n.RuntimeStartedAt = runtimeStartedAt.Time
	}
	if runtimeFirstSeenAt.Valid {
		n.RuntimeFirstSeenAt = runtimeFirstSeenAt.Time
	}
	if runtimeLastSeenAt.Valid {
		n.RuntimeLastSeenAt = runtimeLastSeenAt.Time
	}
	if len(runtimeCapabilities) > 0 {
		if err := json.Unmarshal(runtimeCapabilities, &n.RuntimeCapabilities); err != nil {
			return model.ServerBridgeNode{}, fmt.Errorf("decode server bridge runtime capabilities: %w", err)
		}
	}
	if len(telemetryLatest) > 0 && string(telemetryLatest) != "{}" {
		var telemetry model.ServerBridgeTelemetry
		if err := json.Unmarshal(telemetryLatest, &telemetry); err != nil {
			return model.ServerBridgeNode{}, fmt.Errorf("decode server bridge telemetry: %w", err)
		}
		if telemetry.RuntimeID != "" {
			n.Telemetry = &telemetry
		}
	}
	return n, nil
}

const bridgeNodeSelectV2 = `SELECT id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,status,protocol_version,plugin_version,plugin_sha256,integrity_status,integrity_verified_at,last_heartbeat_at,created_at,rotated_at,runtime_id,runtime_epoch,runtime_previous_id,runtime_transition,runtime_replacement_detected,runtime_started_at,runtime_first_seen_at,runtime_last_seen_at,runtime_uptime_seconds,runtime_process_id,hostname,node_name,minecraft_version,java_version,java_vendor,java_vm_name,runtime_platform,loader_name,loader_version,server_brand,runtime_capabilities,runtime_identity_digest,telemetry_latest FROM server_bridge_nodes_v2`

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
	n.TokenHash = ""
	n.TokenPrefix = ""
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1401, hashtext($1))`, n.ID); err != nil {
		return model.ServerBridgeNode{}, err
	}
	// Registration is intentionally create-only. The node-id advisory lock closes
	// the GET-before-INSERT race between concurrent admin requests; changing an
	// existing identity is allowed only through RotateServerBridgeNodeIdentity,
	// whose HTTP route requires a fresh phishing-resistant admin step-up.
	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM server_bridge_nodes_v2 WHERE id=$1 LIMIT 1`, n.ID).Scan(&existingID)
	if err == nil {
		return model.ServerBridgeNode{}, fmt.Errorf("%w: server bridge node %s already exists", ErrConflict, n.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeNode{}, err
	}
	if n.KeyFingerprint != "" {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1403, hashtext($1))`, n.KeyFingerprint); err != nil {
			return model.ServerBridgeNode{}, err
		}
		var duplicateID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM server_bridge_nodes_v2 WHERE key_fingerprint=$1 LIMIT 1`, n.KeyFingerprint).Scan(&duplicateID)
		if err == nil {
			return model.ServerBridgeNode{}, fmt.Errorf("%w: server bridge node public key is already registered by %s", ErrConflict, duplicateID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeNode{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_nodes_v2(id,name,kind,project_id,profile_id,fingerprint,token_hash,token_prefix,key_algorithm,public_key,key_fingerprint,identity_epoch,identity_rotated_at,status,protocol_version,plugin_version,plugin_sha256,integrity_status,integrity_verified_at,last_heartbeat_at,created_at,rotated_at)
VALUES($1,$2,$3,$4,$5,$6,'','',$7,$8,$9,$10,$11,$12,2,$13,$14,$15,$16,$17,$18,$19)`,
		n.ID, n.Name, n.Kind, n.ProjectID, n.ProfileID, n.Fingerprint, n.KeyAlgorithm, n.PublicKey, n.KeyFingerprint, n.IdentityEpoch, timeArg(n.IdentityRotatedAt), n.Status, n.PluginVersion, n.PluginSHA256, n.IntegrityStatus, timeArg(n.IntegrityVerifiedAt), timeArg(n.LastHeartbeatAt), n.CreatedAt, timeArg(n.RotatedAt))
	if err != nil {
		return model.ServerBridgeNode{}, err
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

func (r *SQLRepository) RotateServerBridgeNodeIdentity(ctx context.Context, id, algorithm, publicKey, fingerprint string, now time.Time) (model.ServerBridgeNode, error) {
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
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1403, hashtext($1))`, fingerprint); err != nil {
		return model.ServerBridgeNode{}, err
	}
	var duplicateID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM server_bridge_nodes_v2 WHERE key_fingerprint=$1 AND id<>$2 LIMIT 1`, fingerprint, id).Scan(&duplicateID)
	if err == nil {
		return model.ServerBridgeNode{}, fmt.Errorf("%w: server bridge node public key is already registered by %s", ErrConflict, duplicateID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeNode{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_runtime_instances_v3 SET ended_at=COALESCE(ended_at,$2),last_seen_at=GREATEST(last_seen_at,$2) WHERE server_id=$1 AND ended_at IS NULL`, id, now.UTC()); err != nil {
		return model.ServerBridgeNode{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET token_hash='',token_prefix='',key_algorithm=$2,public_key=$3,key_fingerprint=$4,identity_epoch=GREATEST(identity_epoch,0)+1,identity_rotated_at=$5,status='active',protocol_version=2,plugin_version='',plugin_sha256='',integrity_status='',integrity_verified_at=NULL,last_heartbeat_at=NULL,runtime_previous_id=runtime_id,runtime_id='',runtime_transition='identity-rotated',runtime_replacement_detected=FALSE,runtime_started_at=NULL,runtime_first_seen_at=NULL,runtime_last_seen_at=NULL,runtime_uptime_seconds=0,runtime_identity_digest='',runtime_identity_signature='',runtime_process_id=0,hostname='',node_name='',minecraft_version='',java_version='',java_vendor='',java_vm_name='',runtime_platform='',loader_name='',loader_version='',server_brand='',runtime_capabilities='[]'::jsonb,telemetry_latest='{}'::jsonb,telemetry_sampled_at=NULL,routing_state='unknown',routing_accepting=FALSE,routing_players_online=0,routing_capacity_max=0,routing_health='unknown',routing_observed_at=NULL,routing_revision=0,routing_digest='',routing_signature='' WHERE id=$1`, id, algorithm, publicKey, fingerprint, now.UTC())
	if err != nil {
		return model.ServerBridgeNode{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return model.ServerBridgeNode{}, ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM server_bridge_node_nonces_v2 WHERE node_id=$1`, id); err != nil {
		return model.ServerBridgeNode{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE server_id=$1 AND status='active'`, id, now.UTC()); err != nil {
		return model.ServerBridgeNode{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE (source_node_id=$1 OR target_node_id=$1) AND status='active'`, id, now.UTC()); err != nil {
		return model.ServerBridgeNode{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ServerBridgeNode{}, err
	}
	return r.GetServerBridgeNode(ctx, id)
}

func (r *SQLRepository) ConsumeServerBridgeNodeNonce(ctx context.Context, nodeID, nonceHash string, identityEpoch int64, consumedAt, expiresAt time.Time) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Expired-nonce cleanup is deliberately not performed on this hot path.
	// 0.14.9 moves cleanup behind a cross-instance PostgreSQL advisory lock so
	// concurrent API replicas do not serialize every signed request on a table-wide DELETE.
	res, err := tx.ExecContext(ctx, `INSERT INTO server_bridge_node_nonces_v2(node_id,nonce_hash,identity_epoch,consumed_at,expires_at)
SELECT id,$2,$3,$4,$5 FROM server_bridge_nodes_v2 WHERE id=$1 AND status='active' AND identity_epoch=$3
ON CONFLICT(node_id,nonce_hash) DO NOTHING`, nodeID, nonceHash, identityEpoch, consumedAt.UTC(), expiresAt.UTC())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
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

func (r *SQLRepository) TouchServerBridgeNodeHeartbeat(ctx context.Context, id, kind, pluginVersion string, protocolVersion int, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	if protocolVersion != 2 && protocolVersion != 3 {
		return fmt.Errorf("unsupported ServerBridge protocol version %d", protocolVersion)
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET fingerprint=CASE WHEN fingerprint='' AND btrim($3)<>'' THEN 'plugin:'||btrim($3) ELSE fingerprint END,protocol_version=$4,last_heartbeat_at=$5 WHERE id=$1 AND status='active' AND kind=lower(btrim($2))`, id, kind, pluginVersion, protocolVersion, now.UTC())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SQLRepository) TouchServerBridgeNodeRuntimeHeartbeat(ctx context.Context, id, kind, pluginVersion string, protocolVersion int, runtime model.ServerBridgeRuntimeIdentity, now time.Time) (model.ServerBridgeRuntimeTransition, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	if protocolVersion != 3 {
		return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("runtime identity requires ServerBridge protocol v3")
	}
	id = strings.TrimSpace(id)
	kind = strings.ToLower(strings.TrimSpace(kind))
	if id == "" || kind == "" || runtime.RuntimeID == "" || runtime.IdentityDigest == "" || runtime.NodeKeyFingerprint == "" {
		return model.ServerBridgeRuntimeTransition{}, ErrConflict
	}
	capabilitiesJSON, err := json.Marshal(runtime.Capabilities)
	if err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1920, hashtext($1))`, id); err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}

	var status, storedKind, keyFingerprint, currentRuntimeID, currentDigest string
	var identityEpoch, runtimeEpoch int64
	var currentStartedAt, currentFirstSeenAt, currentLastSeenAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT status,kind,identity_epoch,key_fingerprint,runtime_id,runtime_epoch,runtime_identity_digest,runtime_started_at,runtime_first_seen_at,runtime_last_seen_at FROM server_bridge_nodes_v2 WHERE id=$1 FOR UPDATE`, id).
		Scan(&status, &storedKind, &identityEpoch, &keyFingerprint, &currentRuntimeID, &runtimeEpoch, &currentDigest, &currentStartedAt, &currentFirstSeenAt, &currentLastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeRuntimeTransition{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	if status != "active" || strings.ToLower(strings.TrimSpace(storedKind)) != kind || strings.ToLower(keyFingerprint) != strings.ToLower(runtime.NodeKeyFingerprint) {
		return model.ServerBridgeRuntimeTransition{}, ErrConflict
	}

	now = now.UTC()
	if currentRuntimeID == runtime.RuntimeID {
		if currentDigest == "" || !strings.EqualFold(currentDigest, runtime.IdentityDigest) {
			return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("%w: runtime identity mutated for existing runtime id", ErrConflict)
		}
		res, err := tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET
			fingerprint=CASE WHEN fingerprint='' AND btrim($3)<>'' THEN 'plugin:'||btrim($3) ELSE fingerprint END,
			protocol_version=$4,last_heartbeat_at=$5,runtime_last_seen_at=$5,runtime_uptime_seconds=$6
			WHERE id=$1 AND status='active' AND kind=lower(btrim($2))`, id, kind, pluginVersion, protocolVersion, now, runtime.UptimeSeconds)
		if err != nil {
			return model.ServerBridgeRuntimeTransition{}, err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return model.ServerBridgeRuntimeTransition{}, ErrNotFound
		}
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_runtime_instances_v3 SET last_seen_at=$4,last_uptime_seconds=$5 WHERE server_id=$1 AND runtime_epoch=$2 AND runtime_id=$3`, id, runtimeEpoch, runtime.RuntimeID, now, runtime.UptimeSeconds); err != nil {
			return model.ServerBridgeRuntimeTransition{}, err
		}
		if err = tx.Commit(); err != nil {
			return model.ServerBridgeRuntimeTransition{}, err
		}
		firstSeen := now
		if currentFirstSeenAt.Valid {
			firstSeen = currentFirstSeenAt.Time
		}
		startedAt := runtime.StartedAt
		if currentStartedAt.Valid {
			startedAt = currentStartedAt.Time
		}
		return model.ServerBridgeRuntimeTransition{RuntimeID: runtime.RuntimeID, RuntimeEpoch: runtimeEpoch, Transition: "unchanged", StartedAt: startedAt, FirstSeenAt: firstSeen, LastSeenAt: now}, nil
	}

	previousRuntimeID := currentRuntimeID
	if previousRuntimeID != "" && currentStartedAt.Valid && !runtime.StartedAt.After(currentStartedAt.Time) {
		return model.ServerBridgeRuntimeTransition{}, fmt.Errorf("%w: runtime instance is older than active runtime", ErrConflict)
	}
	replacementDetected := previousRuntimeID != "" && currentLastSeenAt.Valid && currentLastSeenAt.Time.After(now.Add(-serverBridgeFreshness0149))
	transition := "started"
	if previousRuntimeID != "" {
		if replacementDetected {
			transition = "replacement"
		} else {
			transition = "restart"
		}
	}
	newEpoch := runtimeEpoch + 1
	if newEpoch < 1 {
		newEpoch = 1
	}

	if previousRuntimeID != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_runtime_instances_v3 SET ended_at=COALESCE(ended_at,$3),last_seen_at=GREATEST(last_seen_at,$3) WHERE server_id=$1 AND runtime_epoch=$2`, id, runtimeEpoch, now); err != nil {
			return model.ServerBridgeRuntimeTransition{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_runtime_instances_v3(
		server_id,runtime_epoch,runtime_id,identity_epoch,node_key_fingerprint,identity_digest,identity_signature,process_id,
		started_at,first_seen_at,last_seen_at,last_uptime_seconds,transition,replacement_detected,hostname,node_name,minecraft_version,
		java_version,java_vendor,java_vm_name,runtime_platform,loader_name,loader_version,server_brand,capabilities)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb)`,
		id, newEpoch, runtime.RuntimeID, identityEpoch, strings.ToLower(runtime.NodeKeyFingerprint), strings.ToLower(runtime.IdentityDigest), runtime.IdentitySignature,
		runtime.ProcessID, runtime.StartedAt.UTC(), now, runtime.UptimeSeconds, transition, replacementDetected, runtime.Hostname, runtime.NodeName,
		runtime.MinecraftVersion, runtime.JavaVersion, runtime.JavaVendor, runtime.JavaVMName, runtime.Platform, runtime.LoaderName, runtime.LoaderVersion,
		runtime.ServerBrand, string(capabilitiesJSON))
	if err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET
		fingerprint=CASE WHEN fingerprint='' AND btrim($3)<>'' THEN 'plugin:'||btrim($3) ELSE fingerprint END,
		protocol_version=$4,last_heartbeat_at=$5,
		runtime_previous_id=$6,runtime_id=$7,runtime_epoch=$8,runtime_transition=$9,runtime_replacement_detected=$10,
		runtime_started_at=$11,runtime_first_seen_at=$5,runtime_last_seen_at=$5,runtime_uptime_seconds=$12,runtime_identity_digest=$13,
		runtime_identity_signature=$14,runtime_process_id=$15,hostname=$16,node_name=$17,minecraft_version=$18,java_version=$19,
		java_vendor=$20,java_vm_name=$21,runtime_platform=$22,loader_name=$23,loader_version=$24,server_brand=$25,runtime_capabilities=$26::jsonb,telemetry_latest='{}'::jsonb,telemetry_sampled_at=NULL,routing_state='unknown',routing_accepting=FALSE,routing_players_online=0,routing_capacity_max=0,routing_health='unknown',routing_observed_at=NULL,routing_revision=0,routing_digest='',routing_signature=''
		WHERE id=$1 AND status='active' AND kind=lower(btrim($2)) AND identity_epoch=$27 AND key_fingerprint=$28`,
		id, kind, pluginVersion, protocolVersion, now, previousRuntimeID, runtime.RuntimeID, newEpoch, transition, replacementDetected,
		runtime.StartedAt.UTC(), runtime.UptimeSeconds, strings.ToLower(runtime.IdentityDigest), runtime.IdentitySignature, runtime.ProcessID,
		runtime.Hostname, runtime.NodeName, runtime.MinecraftVersion, runtime.JavaVersion, runtime.JavaVendor, runtime.JavaVMName, runtime.Platform,
		runtime.LoaderName, runtime.LoaderVersion, runtime.ServerBrand, string(capabilitiesJSON), identityEpoch, strings.ToLower(runtime.NodeKeyFingerprint))
	if err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return model.ServerBridgeRuntimeTransition{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeRuntimeTransition{}, err
	}
	return model.ServerBridgeRuntimeTransition{
		RuntimeID: runtime.RuntimeID, RuntimeEpoch: newEpoch, PreviousRuntimeID: previousRuntimeID, Transition: transition,
		ReplacementDetected: replacementDetected, StartedAt: runtime.StartedAt.UTC(), FirstSeenAt: now, LastSeenAt: now,
	}, nil
}

func (r *SQLRepository) SaveServerBridgeTelemetry(ctx context.Context, serverID string, runtimeEpoch int64, telemetry model.ServerBridgeTelemetry, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	serverID = strings.TrimSpace(serverID)
	if serverID == "" || runtimeEpoch < 1 || telemetry.Sequence < 1 || telemetry.RuntimeID == "" {
		return ErrConflict
	}
	payload, err := json.Marshal(telemetry)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1930, hashtext($1))`, serverID); err != nil {
		return err
	}
	var status, currentRuntimeID string
	var currentRuntimeEpoch int64
	err = tx.QueryRowContext(ctx, `SELECT status,runtime_id,runtime_epoch FROM server_bridge_nodes_v2 WHERE id=$1 FOR UPDATE`, serverID).
		Scan(&status, &currentRuntimeID, &currentRuntimeEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" || currentRuntimeEpoch != runtimeEpoch || !strings.EqualFold(currentRuntimeID, telemetry.RuntimeID) {
		return fmt.Errorf("%w: telemetry runtime is not active", ErrConflict)
	}
	telemetry.RuntimeEpoch = runtimeEpoch
	payload, err = json.Marshal(telemetry)
	if err != nil {
		return err
	}
	sampledAt := time.UnixMilli(telemetry.SampledAtUnixMillis).UTC()
	res, err := tx.ExecContext(ctx, `INSERT INTO server_bridge_telemetry_samples_v3(server_id,runtime_epoch,runtime_id,sample_sequence,sampled_at,received_at,payload)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
		ON CONFLICT(server_id,runtime_epoch,sampled_at,sample_sequence) DO NOTHING`,
		serverID, runtimeEpoch, strings.ToLower(telemetry.RuntimeID), telemetry.Sequence, sampledAt, now.UTC(), string(payload))
	if err != nil {
		return err
	}
	inserted, _ := res.RowsAffected()
	if inserted != 1 {
		return fmt.Errorf("%w: duplicate telemetry sample", ErrConflict)
	}
	res, err = tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET telemetry_latest=$4::jsonb,telemetry_sampled_at=$5
		WHERE id=$1 AND runtime_epoch=$2 AND runtime_id=$3 AND (telemetry_sampled_at IS NULL OR telemetry_sampled_at < $5)`,
		serverID, runtimeEpoch, strings.ToLower(telemetry.RuntimeID), string(payload), sampledAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: active runtime changed or telemetry sample is stale", ErrConflict)
	}
	// Keep per-node history bounded even if global maintenance is delayed.
	if telemetry.Sequence%64 == 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM server_bridge_telemetry_samples_v3 t
			USING (
				SELECT ctid FROM server_bridge_telemetry_samples_v3
				WHERE server_id=$1
				ORDER BY sampled_at DESC, runtime_epoch DESC, sample_sequence DESC
				OFFSET 4096 LIMIT 512
			) old
			WHERE t.ctid=old.ctid`, serverID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AppendServerBridgeEvents atomically advances a contiguous per-runtime cursor and
// writes the event row plus the global audit row in the same PostgreSQL transaction.
// Resending an already-ACKed sequence is idempotent only when its digest/event id match.
func (r *SQLRepository) AppendServerBridgeEvents(ctx context.Context, serverID string, runtimeEpoch int64, runtimeID string, events []model.ServerBridgeEvent, now time.Time) (model.ServerBridgeEventAppendResult, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	serverID = strings.TrimSpace(serverID)
	runtimeID = strings.ToLower(strings.TrimSpace(runtimeID))
	if serverID == "" || runtimeEpoch < 1 || len(runtimeID) != 64 || len(events) == 0 || len(events) > 64 {
		return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: invalid server bridge event batch", ErrConflict)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(194, hashtext($1))`, serverID); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	var status, currentRuntimeID string
	var currentRuntimeEpoch int64
	if err = tx.QueryRowContext(ctx, `SELECT status,runtime_id,runtime_epoch FROM server_bridge_nodes_v2 WHERE id=$1 FOR UPDATE`, serverID).Scan(&status, &currentRuntimeID, &currentRuntimeEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeEventAppendResult{}, ErrNotFound
		}
		return model.ServerBridgeEventAppendResult{}, err
	}
	if status != "active" || currentRuntimeEpoch != runtimeEpoch || !strings.EqualFold(strings.TrimSpace(currentRuntimeID), runtimeID) {
		return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event runtime is not active", ErrConflict)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_event_cursors_v3(server_id,runtime_epoch,runtime_id,ack_sequence,updated_at)
		VALUES($1,$2,$3,0,$4) ON CONFLICT(server_id,runtime_epoch) DO NOTHING`, serverID, runtimeEpoch, runtimeID, now.UTC()); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	var ack int64
	var cursorRuntime string
	if err = tx.QueryRowContext(ctx, `SELECT runtime_id,ack_sequence FROM server_bridge_event_cursors_v3 WHERE server_id=$1 AND runtime_epoch=$2 FOR UPDATE`, serverID, runtimeEpoch).Scan(&cursorRuntime, &ack); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(cursorRuntime), runtimeID) {
		return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event cursor runtime mismatch", ErrConflict)
	}
	inserted := 0
	var previousBatchSequence int64
	for i, event := range events {
		if event.Sequence < 1 || event.RuntimeID == "" || !strings.EqualFold(event.RuntimeID, runtimeID) || event.EventID == "" || event.PayloadSHA256 == "" {
			return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: invalid event record", ErrConflict)
		}
		if i > 0 && event.Sequence != previousBatchSequence+1 {
			return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event batch sequence gap", ErrConflict)
		}
		previousBatchSequence = event.Sequence
		if event.Sequence <= ack {
			var storedDigest, storedEventID, storedType, storedSignature string
			err = tx.QueryRowContext(ctx, `SELECT payload_sha256,event_id,event_type,signature FROM server_bridge_events_v3 WHERE server_id=$1 AND runtime_epoch=$2 AND sequence=$3`, serverID, runtimeEpoch, event.Sequence).Scan(&storedDigest, &storedEventID, &storedType, &storedSignature)
			if err != nil || !strings.EqualFold(storedDigest, event.PayloadSHA256) || storedEventID != event.EventID || storedType != event.Type || storedSignature != event.Signature {
				return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: conflicting event replay", ErrConflict)
			}
			continue
		}
		if event.Sequence != ack+1 {
			return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: event sequence gap", ErrConflict)
		}
		payload, marshalErr := json.Marshal(event.Payload)
		if marshalErr != nil {
			return model.ServerBridgeEventAppendResult{}, marshalErr
		}
		occurredAt := time.UnixMilli(event.OccurredAtUnixMillis).UTC()
		res, execErr := tx.ExecContext(ctx, `INSERT INTO server_bridge_events_v3(server_id,runtime_epoch,runtime_id,sequence,event_id,event_type,occurred_at,payload,payload_sha256,signature,received_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11) ON CONFLICT(server_id,runtime_epoch,sequence) DO NOTHING`,
			serverID, runtimeEpoch, runtimeID, event.Sequence, event.EventID, event.Type, occurredAt, string(payload), strings.ToLower(event.PayloadSHA256), event.Signature, now.UTC())
		if execErr != nil {
			return model.ServerBridgeEventAppendResult{}, execErr
		}
		rows, _ := res.RowsAffected()
		if rows != 1 {
			var storedDigest, storedEventID, storedType, storedSignature string
			if err = tx.QueryRowContext(ctx, `SELECT payload_sha256,event_id,event_type,signature FROM server_bridge_events_v3 WHERE server_id=$1 AND runtime_epoch=$2 AND sequence=$3`, serverID, runtimeEpoch, event.Sequence).Scan(&storedDigest, &storedEventID, &storedType, &storedSignature); err != nil || !strings.EqualFold(storedDigest, event.PayloadSHA256) || storedEventID != event.EventID || storedType != event.Type || storedSignature != event.Signature {
				return model.ServerBridgeEventAppendResult{}, fmt.Errorf("%w: conflicting event replay", ErrConflict)
			}
		} else {
			inserted++
			auditID := fmt.Sprintf("serverbridge-event-%s-%d-%d", serverID, runtimeEpoch, event.Sequence)
			target := fmt.Sprintf("%s:%s:%d:%s", serverID, runtimeID, event.Sequence, event.EventID)
			if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,$3,$4,'','ServerBridge event stream',$5) ON CONFLICT(id) DO NOTHING`,
				auditID, serverID, "serverbridge:event:"+event.Type, target, now.UTC()); err != nil {
				return model.ServerBridgeEventAppendResult{}, err
			}
			if err = r.applyPlayerLifecycleEventTx0197(ctx, tx, serverID, event, now); err != nil {
				return model.ServerBridgeEventAppendResult{}, err
			}
		}
		ack = event.Sequence
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_event_cursors_v3 SET ack_sequence=$3,runtime_id=$4,updated_at=$5 WHERE server_id=$1 AND runtime_epoch=$2`, serverID, runtimeEpoch, ack, runtimeID, now.UTC()); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeEventAppendResult{}, err
	}
	return model.ServerBridgeEventAppendResult{AckSequence: ack, Inserted: inserted}, nil
}

func scanBridgeJoin(row interface{ Scan(...any) error }) (model.ServerBridgeJoinTicket, error) {
	var j model.ServerBridgeJoinTicket
	var consumed sql.NullTime
	err := row.Scan(&j.ID, &j.TicketVersion, &j.Username, &j.UsernameNormalized, &j.UUID, &j.UserID, &j.SessionID, &j.ServerID, &j.ProjectID, &j.ProfileID, &j.Channel, &j.AccessTokenHash, &j.TrustedDeviceID, &j.BindingEpoch, &j.MinecraftSessionID, &j.ProtocolVersion, &j.IssuedIdentityEpoch, &j.IssuedKeyFingerprint, &j.Status, &j.CreatedAt, &j.ExpiresAt, &consumed, &j.RedeemedIdentityEpoch, &j.RedeemedKeyFingerprint, &j.RedeemedNonceHash, &j.RedeemedByIP, &j.SessionCorrelationID)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if consumed.Valid {
		j.ConsumedAt = consumed.Time
	}
	return j, nil
}

const bridgeJoinSelectV2 = `SELECT id,ticket_version,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),protocol_version,issued_identity_epoch,issued_key_fingerprint,status,created_at,expires_at,consumed_at,redeemed_identity_epoch,redeemed_key_fingerprint,redeemed_nonce_hash,redeemed_by_ip,session_correlation_id FROM server_bridge_join_tickets_v2`

func (r *SQLRepository) CreateServerBridgeJoinTicket(ctx context.Context, j model.ServerBridgeJoinTicket) (model.ServerBridgeJoinTicket, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	j.Username = strings.TrimSpace(j.Username)
	j.UsernameNormalized = strings.ToLower(j.Username)
	j.ServerID = strings.TrimSpace(j.ServerID)
	j.ProjectID = strings.TrimSpace(j.ProjectID)
	j.ProfileID = strings.TrimSpace(j.ProfileID)
	j.TicketVersion = 2
	if j.ProtocolVersion == 0 {
		j.ProtocolVersion = 2
	}
	if j.ProtocolVersion != 2 && j.ProtocolVersion != 3 {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("unsupported ServerBridge protocol version %d", j.ProtocolVersion)
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
	var status, projectID, profileID, keyFingerprint string
	var identityEpoch int64
	var nodeProtocolVersion int
	err = tx.QueryRowContext(ctx, `SELECT status,project_id,profile_id,identity_epoch,key_fingerprint,protocol_version FROM server_bridge_nodes_v2 WHERE id=$1 FOR SHARE`, j.ServerID).Scan(&status, &projectID, &profileID, &identityEpoch, &keyFingerprint, &nodeProtocolVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeJoinTicket{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if status != "active" || identityEpoch < 1 || len(keyFingerprint) != 64 {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server bridge node identity is not active")
	}
	if projectID != "" && projectID != j.ProjectID {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server project binding mismatch")
	}
	if profileID != "" && profileID != j.ProfileID {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server profile binding mismatch")
	}
	if nodeProtocolVersion != 2 && nodeProtocolVersion != 3 {
		return model.ServerBridgeJoinTicket{}, fmt.Errorf("server bridge node has unsupported protocol version %d", nodeProtocolVersion)
	}
	j.ProtocolVersion = nodeProtocolVersion
	j.IssuedIdentityEpoch = identityEpoch
	j.IssuedKeyFingerprint = keyFingerprint
	_, err = tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='replaced',invalidated_at=$3 WHERE server_id=$1 AND username_normalized=$2 AND status='active'`, j.ServerID, j.UsernameNormalized, j.CreatedAt)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_join_tickets_v2(id,ticket_version,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,trusted_device_id,binding_epoch,minecraft_session_id,protocol_version,issued_identity_epoch,issued_key_fingerprint,status,created_at,expires_at,session_correlation_id) VALUES($1,2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),$13,NULLIF($14,''),$15,$16,$17,'active',$18,$19,$20)`, j.ID, j.Username, j.UsernameNormalized, j.UUID, j.UserID, j.SessionID, j.ServerID, j.ProjectID, j.ProfileID, j.Channel, j.AccessTokenHash, j.TrustedDeviceID, j.BindingEpoch, j.MinecraftSessionID, j.ProtocolVersion, j.IssuedIdentityEpoch, j.IssuedKeyFingerprint, j.CreatedAt.UTC(), j.ExpiresAt.UTC(), strings.ToLower(strings.TrimSpace(j.SessionCorrelationID)))
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
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

func (r *SQLRepository) ConsumeServerBridgeJoinTicket(ctx context.Context, id string, redemption model.ServerBridgeJoinRedemption, now time.Time) (model.ServerBridgeJoinTicket, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	id = strings.TrimSpace(id)
	redemption.NodeID = strings.TrimSpace(redemption.NodeID)
	redemption.KeyFingerprint = strings.ToLower(strings.TrimSpace(redemption.KeyFingerprint))
	redemption.NonceHash = strings.ToLower(strings.TrimSpace(redemption.NonceHash))
	redemption.RemoteIP = strings.TrimSpace(redemption.RemoteIP)
	redemption.SessionCorrelationID = strings.ToLower(strings.TrimSpace(redemption.SessionCorrelationID))
	if id == "" || redemption.NodeID == "" || redemption.IdentityEpoch < 1 || len(redemption.KeyFingerprint) != 64 || len(redemption.NonceHash) != 64 {
		return model.ServerBridgeJoinTicket{}, ErrConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	defer tx.Rollback()
	q := `UPDATE server_bridge_join_tickets_v2 AS j
SET status='consumed',consumed_at=$6,redeemed_identity_epoch=$3,redeemed_key_fingerprint=$4,redeemed_nonce_hash=$5,redeemed_by_ip=$7
WHERE j.id=$1 AND j.server_id=$2 AND j.ticket_version=2 AND j.status='active' AND j.expires_at>$6
  AND j.issued_identity_epoch=$3 AND j.issued_key_fingerprint=$4
  AND EXISTS (SELECT 1 FROM server_bridge_nodes_v2 n WHERE n.id=j.server_id AND n.status='active' AND n.identity_epoch=$3 AND n.key_fingerprint=$4)
RETURNING id,ticket_version,username,username_normalized,player_uuid,user_id,session_id,server_id,project_id,profile_id,channel,access_token_hash,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),protocol_version,issued_identity_epoch,issued_key_fingerprint,status,created_at,expires_at,consumed_at,redeemed_identity_epoch,redeemed_key_fingerprint,redeemed_nonce_hash,redeemed_by_ip,session_correlation_id`
	j, err := scanBridgeJoin(tx.QueryRowContext(ctx, q, id, redemption.NodeID, redemption.IdentityEpoch, redemption.KeyFingerprint, redemption.NonceHash, now.UTC(), redemption.RemoteIP))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeJoinTicket{}, ErrConflict
	}
	if err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if err = r.activatePlayerSessionTx0197(ctx, tx, j, redemption, now); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeJoinTicket{}, err
	}
	return j, nil
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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	q := `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$3 WHERE session_id=$1 AND ($2='' OR server_id=$2) AND status='active'`
	res, err := tx.ExecContext(ctx, q, sessionID, serverID, now.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	hRes, err := tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$3 WHERE session_id=$1 AND ($2='' OR target_node_id=$2 OR source_node_id=$2) AND status='active'`, sessionID, serverID, now.UTC())
	if err != nil {
		return int(n), err
	}
	hn, _ := hRes.RowsAffected()
	pn, err := r.invalidatePlayerSessionsBySessionTx0197(ctx, tx, sessionID, serverID, "never-session-invalidated", now)
	if err != nil {
		return int(n + hn), err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return int(n+hn) + pn, nil
}

func (r *SQLRepository) InvalidateServerBridgeUser(ctx context.Context, userID string, now time.Time) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=$2 WHERE user_id=$1 AND status='active'`, userID, now.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	hRes, err := tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE user_id=$1 AND status='active'`, userID, now.UTC())
	if err != nil {
		return int(n), err
	}
	hn, _ := hRes.RowsAffected()
	pn, err := r.invalidatePlayerSessionsByUserTx0197(ctx, tx, userID, "user-invalidated", now)
	if err != nil {
		return int(n + hn), err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return int(n+hn) + pn, nil
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
	var nodes, joins, handoffs, textures int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_nodes_v2`).Scan(&nodes); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active' AND expires_at>$1::timestamptz`, now.UTC()).Scan(&joins); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_handoffs_v2 WHERE status='active' AND expires_at>$1::timestamptz`, now.UTC()).Scan(&handoffs); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_textures_v2`).Scan(&textures); err != nil {
		return nil, err
	}
	ha, err := r.ServerBridgeHAStatus(ctx, now)
	if err != nil {
		return nil, err
	}
	return map[string]any{"servers": nodes, "activeJoins": joins, "activeHandoffs": handoffs, "topologyEdges": ha.TopologyFresh, "topologyEdgesStoredActive": ha.TopologyActive, "staleTopologyEdges": ha.TopologyStale, "freshNodes": ha.NodesFresh, "staleNodes": ha.NodesStale, "textures": textures, "joinTtlSeconds": 120, "handoffTtlSeconds": 30, "topologyFreshnessSeconds": ha.FreshnessSeconds, "topologyMode": "runtime-learned-zero-patch", "nodeAuthentication": "ed25519-signed-requests", "replayProtection": "postgresql-single-use-nonce", "protocolVersion": 3, "supportedProtocolVersions": []int{3, 2}, "sourceOfTruth": "postgresql"}, nil
}

func isProxyBridgeKind0148(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity", "bungeecord", "waterfall":
		return true
	default:
		return false
	}
}

func isBackendBridgeKind0148(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "bukkit", "spigot", "paper", "purpur", "folia", "fabric", "forge", "neoforge":
		return true
	default:
		return false
	}
}

func scanServerBridgeHandoff(row interface{ Scan(...any) error }) (model.ServerBridgeHandoff, error) {
	var h model.ServerBridgeHandoff
	var consumed sql.NullTime
	err := row.Scan(&h.ID, &h.Username, &h.UsernameNormalized, &h.UUID, &h.UserID, &h.SessionID,
		&h.SourceNodeID, &h.TargetNodeID, &h.BackendName, &h.ProjectID, &h.ProfileID, &h.Channel,
		&h.TrustedDeviceID, &h.BindingEpoch, &h.MinecraftSessionID,
		&h.SourceIdentityEpoch, &h.SourceKeyFingerprint, &h.TargetIdentityEpoch, &h.TargetKeyFingerprint, &h.ProtocolVersion,
		&h.SourceRuntimeID, &h.SourceRuntimeEpoch, &h.SourceRoutingRevision, &h.SourceRoutingDigest, &h.SourceRoutingSignature,
		&h.TargetRuntimeID, &h.TargetRuntimeEpoch, &h.TargetRoutingRevision, &h.TargetRoutingDigest, &h.TargetRoutingSignature,
		&h.Status, &h.CreatedAt, &h.ExpiresAt, &consumed, &h.RedeemedNonceHash, &h.RedeemedByIP, &h.SessionCorrelationID, &h.TransferSequence)
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if consumed.Valid {
		h.ConsumedAt = consumed.Time
	}
	return h, nil
}

const bridgeHandoffSelect0148 = `SELECT id,username,username_normalized,player_uuid,user_id,session_id,source_node_id,target_node_id,backend_name,project_id,profile_id,channel,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),source_identity_epoch,source_key_fingerprint,target_identity_epoch,target_key_fingerprint,protocol_version,source_runtime_id,source_runtime_epoch,source_routing_revision,source_routing_digest,source_routing_signature,target_runtime_id,target_runtime_epoch,target_routing_revision,target_routing_digest,target_routing_signature,status,created_at,expires_at,consumed_at,redeemed_nonce_hash,redeemed_by_ip,session_correlation_id,transfer_sequence FROM server_bridge_handoffs_v2`

// CreateServerBridgeHandoff mints a target-specific credential only from a very
// recent join ticket already redeemed by the authenticated proxy. The target is
// resolved by canonical node id first, then by unique node name. This is what
// allows zero-patch installs to use the proxy's existing backend name directly.
func (r *SQLRepository) CreateServerBridgeHandoff(ctx context.Context, h model.ServerBridgeHandoff, now time.Time) (model.ServerBridgeHandoff, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	h.SourceNodeID = strings.TrimSpace(h.SourceNodeID)
	targetRef := strings.TrimSpace(h.TargetNodeID)
	h.Username = strings.TrimSpace(h.Username)
	h.UsernameNormalized = strings.ToLower(h.Username)
	if h.ID == "" || h.SourceNodeID == "" || targetRef == "" || h.UsernameNormalized == "" {
		return model.ServerBridgeHandoff{}, ErrConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	defer tx.Rollback()
	lockKey := h.SourceNodeID + ":" + h.UsernameNormalized + ":" + strings.ToLower(targetRef)
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1408, hashtext($1))`, lockKey); err != nil {
		return model.ServerBridgeHandoff{}, err
	}

	var sourceKind, sourceStatus, sourceFingerprint, sourceRuntimeID, sourceRouteState, sourceRouteHealth, sourceRouteDigest, sourceRouteSignature string
	var sourceEpoch, sourceRuntimeEpoch, sourceRouteRevision int64
	var sourceProtocolVersion int
	var sourceRouteAccepting bool
	var sourceHeartbeat, sourceRouteObserved sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT kind,status,identity_epoch,key_fingerprint,runtime_id,runtime_epoch,routing_state,routing_health,routing_accepting,routing_revision,routing_digest,routing_signature,last_heartbeat_at,routing_observed_at,protocol_version FROM server_bridge_nodes_v2 WHERE id=$1 FOR SHARE`, h.SourceNodeID).
		Scan(&sourceKind, &sourceStatus, &sourceEpoch, &sourceFingerprint, &sourceRuntimeID, &sourceRuntimeEpoch, &sourceRouteState, &sourceRouteHealth, &sourceRouteAccepting, &sourceRouteRevision, &sourceRouteDigest, &sourceRouteSignature, &sourceHeartbeat, &sourceRouteObserved, &sourceProtocolVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeHandoff{}, ErrNotFound
		}
		return model.ServerBridgeHandoff{}, err
	}
	freshAfter := now.UTC().Add(-serverBridgeRoutingFreshness0196)
	if sourceStatus != "active" || !isProxyBridgeKind0148(sourceKind) || sourceEpoch < 1 || len(sourceFingerprint) != 64 {
		return model.ServerBridgeHandoff{}, fmt.Errorf("source node is not an active proxy")
	}
	routingV3 := h.RequireRoutingProof && sourceProtocolVersion >= 3
	if routingV3 {
		if len(sourceRuntimeID) != 64 || sourceRuntimeEpoch < 1 || sourceRouteRevision < 1 || len(sourceRouteDigest) != 64 || sourceRouteSignature == "" ||
			!sourceHeartbeat.Valid || sourceHeartbeat.Time.Before(freshAfter) || !sourceRouteObserved.Valid || sourceRouteObserved.Time.Before(freshAfter) ||
			sourceRouteState != "ready" || !sourceRouteAccepting || sourceRouteHealth == "unhealthy" {
			return model.ServerBridgeHandoff{}, fmt.Errorf("source node is not a routable proxy")
		}
		h.SourceRuntimeID = strings.ToLower(sourceRuntimeID)
		h.SourceRuntimeEpoch = sourceRuntimeEpoch
		h.SourceRoutingRevision = sourceRouteRevision
		h.SourceRoutingDigest = strings.ToLower(sourceRouteDigest)
		h.SourceRoutingSignature = sourceRouteSignature
	}

	var targetID, targetName, targetKind, targetStatus, targetProject, targetProfile, targetFingerprint string
	var targetRuntimeID, targetRouteState, targetRouteHealth, targetRouteDigest, targetRouteSignature string
	var targetEpoch, targetRuntimeEpoch, targetRouteRevision int64
	var targetProtocolVersion, targetPlayers, targetCapacity int
	var targetRouteAccepting bool
	var targetHeartbeat, targetRouteObserved sql.NullTime
	rows, err := tx.QueryContext(ctx, `SELECT id,name,kind,status,project_id,profile_id,identity_epoch,key_fingerprint,protocol_version,runtime_id,runtime_epoch,routing_state,routing_health,routing_accepting,routing_players_online,routing_capacity_max,routing_revision,routing_digest,routing_signature,last_heartbeat_at,routing_observed_at FROM server_bridge_nodes_v2 WHERE id=$1 OR lower(name)=lower($1) ORDER BY CASE WHEN id=$1 THEN 0 ELSE 1 END,id LIMIT 2 FOR UPDATE`, targetRef)
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	defer rows.Close()
	matches := 0
	for rows.Next() {
		matches++
		if matches == 1 {
			if err = rows.Scan(&targetID, &targetName, &targetKind, &targetStatus, &targetProject, &targetProfile, &targetEpoch, &targetFingerprint, &targetProtocolVersion, &targetRuntimeID, &targetRuntimeEpoch, &targetRouteState, &targetRouteHealth, &targetRouteAccepting, &targetPlayers, &targetCapacity, &targetRouteRevision, &targetRouteDigest, &targetRouteSignature, &targetHeartbeat, &targetRouteObserved); err != nil {
				return model.ServerBridgeHandoff{}, err
			}
		}
	}
	if err = rows.Err(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if err = rows.Close(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if matches == 0 {
		return model.ServerBridgeHandoff{}, ErrNotFound
	}
	if targetID != targetRef && matches > 1 {
		return model.ServerBridgeHandoff{}, fmt.Errorf("%w: backend name %s is ambiguous", ErrConflict, targetRef)
	}
	if targetStatus != "active" || !isBackendBridgeKind0148(targetKind) || targetEpoch < 1 || len(targetFingerprint) != 64 {
		return model.ServerBridgeHandoff{}, fmt.Errorf("target node is not an active backend")
	}
	if routingV3 {
		if len(targetRuntimeID) != 64 || targetRuntimeEpoch < 1 || targetRouteRevision < 1 || len(targetRouteDigest) != 64 || targetRouteSignature == "" ||
			!targetHeartbeat.Valid || targetHeartbeat.Time.Before(freshAfter) || !targetRouteObserved.Valid || targetRouteObserved.Time.Before(freshAfter) ||
			targetRouteState != "ready" || !targetRouteAccepting || (targetRouteHealth != "healthy" && targetRouteHealth != "degraded") ||
			(targetCapacity > 0 && targetPlayers >= targetCapacity) {
			return model.ServerBridgeHandoff{}, fmt.Errorf("target node is unhealthy, draining, in maintenance, stale, or at capacity")
		}
		if targetCapacity > 0 {
			var reservations int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM server_bridge_handoffs_v2 WHERE target_node_id=$1 AND ((status='active' AND expires_at>$2) OR (status='consumed' AND consumed_at>$2::timestamptz-interval '30 seconds'))`, targetID, now.UTC()).Scan(&reservations); err != nil {
				return model.ServerBridgeHandoff{}, err
			}
			if targetPlayers+reservations >= targetCapacity {
				return model.ServerBridgeHandoff{}, fmt.Errorf("target node has no unreserved capacity")
			}
		}
	}
	if targetProtocolVersion != 2 && targetProtocolVersion != 3 {
		return model.ServerBridgeHandoff{}, fmt.Errorf("target node has unsupported ServerBridge protocol version %d", targetProtocolVersion)
	}
	if routingV3 {
		h.TargetRuntimeID = strings.ToLower(targetRuntimeID)
		h.TargetRuntimeEpoch = targetRuntimeEpoch
		h.TargetRoutingRevision = targetRouteRevision
		h.TargetRoutingDigest = strings.ToLower(targetRouteDigest)
		h.TargetRoutingSignature = targetRouteSignature
	}

	// The source proof is the latest successfully consumed launcher ticket for an
	// auth session that is still active and on the same binding epoch. This keeps
	// later proxy server switches working without replaying the launcher ticket.
	var sourceJoin model.ServerBridgeJoinTicket
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, bridgeJoinSelectV2+` WHERE server_id=$1 AND username_normalized=$2 AND status='consumed' AND EXISTS (SELECT 1 FROM auth_sessions a WHERE a.id=server_bridge_join_tickets_v2.session_id AND a.user_id=server_bridge_join_tickets_v2.user_id AND a.status='active' AND a.expires_at>$3 AND a.binding_epoch=server_bridge_join_tickets_v2.binding_epoch) ORDER BY consumed_at DESC LIMIT 1`, h.SourceNodeID, h.UsernameNormalized, now.UTC()).
		Scan(&sourceJoin.ID, &sourceJoin.TicketVersion, &sourceJoin.Username, &sourceJoin.UsernameNormalized, &sourceJoin.UUID, &sourceJoin.UserID, &sourceJoin.SessionID, &sourceJoin.ServerID, &sourceJoin.ProjectID, &sourceJoin.ProfileID, &sourceJoin.Channel, &sourceJoin.AccessTokenHash, &sourceJoin.TrustedDeviceID, &sourceJoin.BindingEpoch, &sourceJoin.MinecraftSessionID, &sourceJoin.ProtocolVersion, &sourceJoin.IssuedIdentityEpoch, &sourceJoin.IssuedKeyFingerprint, &sourceJoin.Status, &sourceJoin.CreatedAt, &sourceJoin.ExpiresAt, &consumedAt, &sourceJoin.RedeemedIdentityEpoch, &sourceJoin.RedeemedKeyFingerprint, &sourceJoin.RedeemedNonceHash, &sourceJoin.RedeemedByIP, &sourceJoin.SessionCorrelationID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeHandoff{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if !consumedAt.Valid || sourceJoin.RedeemedIdentityEpoch != sourceEpoch || !strings.EqualFold(sourceJoin.RedeemedKeyFingerprint, sourceFingerprint) {
		return model.ServerBridgeHandoff{}, fmt.Errorf("source join was not redeemed by current proxy identity")
	}
	if targetProject != "" && targetProject != sourceJoin.ProjectID {
		return model.ServerBridgeHandoff{}, fmt.Errorf("target project binding mismatch")
	}
	if targetProfile != "" && targetProfile != sourceJoin.ProfileID {
		return model.ServerBridgeHandoff{}, fmt.Errorf("target profile binding mismatch")
	}

	h.Username = sourceJoin.Username
	h.UsernameNormalized = sourceJoin.UsernameNormalized
	h.UUID = sourceJoin.UUID
	h.UserID = sourceJoin.UserID
	h.SessionID = sourceJoin.SessionID
	h.TargetNodeID = targetID
	h.BackendName = targetName
	h.ProjectID = sourceJoin.ProjectID
	h.ProfileID = sourceJoin.ProfileID
	h.Channel = sourceJoin.Channel
	h.TrustedDeviceID = sourceJoin.TrustedDeviceID
	h.BindingEpoch = sourceJoin.BindingEpoch
	expectedCorrelation := strings.ToLower(strings.TrimSpace(h.SessionCorrelationID))
	if expectedCorrelation != "" && !strings.EqualFold(expectedCorrelation, sourceJoin.SessionCorrelationID) {
		return model.ServerBridgeHandoff{}, fmt.Errorf("%w: session correlation proof mismatch", ErrConflict)
	}
	h.MinecraftSessionID = sourceJoin.MinecraftSessionID
	// A lifecycle transfer is runtime-bound. The explicit 0.19.7 correlation
	// proof therefore requires v3 + Routing 2 on both ends; older rolling-upgrade
	// paths continue with the pre-0.19.7 handoff without fabricating a runtime.
	lifecycleTransfer := sourceJoin.ProtocolVersion >= 3 && targetProtocolVersion >= 3 && routingV3 && len(h.SourceRuntimeID) == 64 && h.SourceRuntimeEpoch > 0 && len(h.TargetRuntimeID) == 64 && h.TargetRuntimeEpoch > 0
	if expectedCorrelation != "" && !lifecycleTransfer {
		return model.ServerBridgeHandoff{}, fmt.Errorf("%w: player session transfer requires v3 runtime-bound source and target", ErrConflict)
	}
	if lifecycleTransfer {
		h.SessionCorrelationID = strings.ToLower(strings.TrimSpace(sourceJoin.SessionCorrelationID))
	} else {
		h.SessionCorrelationID = ""
	}
	h.SourceIdentityEpoch = sourceEpoch
	h.SourceKeyFingerprint = strings.ToLower(sourceFingerprint)
	h.TargetIdentityEpoch = targetEpoch
	h.TargetKeyFingerprint = strings.ToLower(targetFingerprint)
	h.ProtocolVersion = targetProtocolVersion
	h.Status = "active"
	h.CreatedAt = now.UTC()
	if h.ExpiresAt.IsZero() || h.ExpiresAt.After(now.UTC().Add(30*time.Second)) {
		h.ExpiresAt = now.UTC().Add(30 * time.Second)
	}

	if h.SessionCorrelationID != "" {
		if err = r.issuePlayerTransferTx0197(ctx, tx, &h, expectedCorrelation, now); err != nil {
			return model.ServerBridgeHandoff{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='replaced',invalidated_at=$3 WHERE target_node_id=$1 AND username_normalized=$2 AND status='active'`, h.TargetNodeID, h.UsernameNormalized, now.UTC()); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_handoffs_v2(id,username,username_normalized,player_uuid,user_id,session_id,source_node_id,target_node_id,backend_name,project_id,profile_id,channel,trusted_device_id,binding_epoch,minecraft_session_id,source_identity_epoch,source_key_fingerprint,target_identity_epoch,target_key_fingerprint,protocol_version,source_runtime_id,source_runtime_epoch,source_routing_revision,source_routing_digest,source_routing_signature,target_runtime_id,target_runtime_epoch,target_routing_revision,target_routing_digest,target_routing_signature,status,created_at,expires_at,session_correlation_id,transfer_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),$14,NULLIF($15,''),$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,'active',$31,$32,$33,$34)`, h.ID, h.Username, h.UsernameNormalized, h.UUID, h.UserID, h.SessionID, h.SourceNodeID, h.TargetNodeID, h.BackendName, h.ProjectID, h.ProfileID, h.Channel, h.TrustedDeviceID, h.BindingEpoch, h.MinecraftSessionID, h.SourceIdentityEpoch, h.SourceKeyFingerprint, h.TargetIdentityEpoch, h.TargetKeyFingerprint, h.ProtocolVersion, h.SourceRuntimeID, h.SourceRuntimeEpoch, h.SourceRoutingRevision, h.SourceRoutingDigest, h.SourceRoutingSignature, h.TargetRuntimeID, h.TargetRuntimeEpoch, h.TargetRoutingRevision, h.TargetRoutingDigest, h.TargetRoutingSignature, h.CreatedAt, h.ExpiresAt, h.SessionCorrelationID, h.TransferSequence); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if err = r.recordPlayerTransferTx0197(ctx, tx, h, now); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_topology_edges_v2(source_node_id,target_node_id,backend_name,project_id,profile_id,status,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,'active',$6,$6) ON CONFLICT(source_node_id,target_node_id) DO UPDATE SET backend_name=EXCLUDED.backend_name,project_id=EXCLUDED.project_id,profile_id=EXCLUDED.profile_id,status='active',last_seen_at=EXCLUDED.last_seen_at`, h.SourceNodeID, h.TargetNodeID, h.BackendName, h.ProjectID, h.ProfileID, now.UTC()); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	return h, nil
}

func (r *SQLRepository) GetActiveServerBridgeHandoff(ctx context.Context, username, targetNodeID string, now time.Time) (model.ServerBridgeHandoff, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	h, err := scanServerBridgeHandoff(r.db.QueryRowContext(ctx, bridgeHandoffSelect0148+` WHERE target_node_id=$1 AND username_normalized=$2 AND status='active' AND expires_at>$3 ORDER BY created_at DESC LIMIT 1`, strings.TrimSpace(targetNodeID), strings.ToLower(strings.TrimSpace(username)), now.UTC()))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeHandoff{}, ErrNotFound
	}
	return h, err
}

func (r *SQLRepository) ConsumeServerBridgeHandoff(ctx context.Context, id string, redemption model.ServerBridgeJoinRedemption, now time.Time) (model.ServerBridgeHandoff, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	redemption.NodeID = strings.TrimSpace(redemption.NodeID)
	redemption.KeyFingerprint = strings.ToLower(strings.TrimSpace(redemption.KeyFingerprint))
	redemption.NonceHash = strings.ToLower(strings.TrimSpace(redemption.NonceHash))
	redemption.SessionCorrelationID = strings.ToLower(strings.TrimSpace(redemption.SessionCorrelationID))
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	defer tx.Rollback()
	q := `UPDATE server_bridge_handoffs_v2 h SET status='consumed',consumed_at=$5,redeemed_nonce_hash=$4,redeemed_by_ip=$6 WHERE h.id=$1 AND h.target_node_id=$2 AND h.status='active' AND h.expires_at>$5 AND h.target_identity_epoch=$3 AND h.target_key_fingerprint=$7 AND EXISTS (SELECT 1 FROM server_bridge_nodes_v2 n WHERE n.id=h.target_node_id AND n.status='active' AND n.identity_epoch=$3 AND n.key_fingerprint=$7 AND (h.target_runtime_id='' OR (n.runtime_id=h.target_runtime_id AND n.runtime_epoch=h.target_runtime_epoch AND n.routing_state='ready' AND n.routing_accepting=TRUE AND n.routing_health IN ('healthy','degraded') AND n.last_heartbeat_at>$5::timestamptz-interval '90 seconds' AND n.routing_observed_at>$5::timestamptz-interval '90 seconds' AND (n.routing_capacity_max=0 OR n.routing_players_online<n.routing_capacity_max)))) RETURNING id,username,username_normalized,player_uuid,user_id,session_id,source_node_id,target_node_id,backend_name,project_id,profile_id,channel,COALESCE(trusted_device_id,''),binding_epoch,COALESCE(minecraft_session_id,''),source_identity_epoch,source_key_fingerprint,target_identity_epoch,target_key_fingerprint,protocol_version,source_runtime_id,source_runtime_epoch,source_routing_revision,source_routing_digest,source_routing_signature,target_runtime_id,target_runtime_epoch,target_routing_revision,target_routing_digest,target_routing_signature,status,created_at,expires_at,consumed_at,redeemed_nonce_hash,redeemed_by_ip,session_correlation_id,transfer_sequence`
	h, err := scanServerBridgeHandoff(tx.QueryRowContext(ctx, q, strings.TrimSpace(id), redemption.NodeID, redemption.IdentityEpoch, redemption.NonceHash, now.UTC(), strings.TrimSpace(redemption.RemoteIP), redemption.KeyFingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeHandoff{}, ErrConflict
	}
	if err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if err = r.consumePlayerTransferTx0197(ctx, tx, h, redemption, now); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeHandoff{}, err
	}
	return h, nil
}

func (r *SQLRepository) InvalidateServerBridgeHandoff(ctx context.Context, id string, now time.Time) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE id=$1 AND status='active'`, strings.TrimSpace(id), now.UTC())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

const serverBridgeFreshness0149 = 2 * time.Minute

func (r *SQLRepository) ListServerBridgeTopology(ctx context.Context) ([]model.ServerBridgeTopologyEdge, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	// Topology & Routing 2 derives the live graph from authenticated node/runtime
	// advertisements instead of waiting for the first successful handoff to create
	// an edge. Historical observed edges are joined only for created/last-seen
	// metadata; routing eligibility is always recomputed from current node state.
	rows, err := r.db.QueryContext(ctx, `SELECT
s.id,t.id,t.name,s.project_id,t.profile_id,
CASE
 WHEN s.status<>'active' OR s.last_heartbeat_at<=CURRENT_TIMESTAMP-interval '90 seconds' OR s.routing_observed_at<=CURRENT_TIMESTAMP-interval '90 seconds' THEN 'source-stale'
 WHEN s.routing_state='maintenance' THEN 'source-maintenance'
 WHEN s.routing_state='draining' THEN 'source-draining'
 WHEN s.routing_health='unhealthy' OR NOT s.routing_accepting THEN 'source-unhealthy'
 WHEN t.status<>'active' OR t.last_heartbeat_at<=CURRENT_TIMESTAMP-interval '90 seconds' OR t.routing_observed_at<=CURRENT_TIMESTAMP-interval '90 seconds' THEN 'stale'
 WHEN t.routing_state='maintenance' THEN 'maintenance'
 WHEN t.routing_state='draining' THEN 'draining'
 WHEN t.routing_health='unhealthy' OR NOT t.routing_accepting THEN 'unhealthy'
 WHEN t.routing_capacity_max>0 AND t.routing_players_online + COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 hcap WHERE hcap.target_node_id=t.id AND ((hcap.status='active' AND hcap.expires_at>CURRENT_TIMESTAMP) OR (hcap.status='consumed' AND hcap.consumed_at>CURRENT_TIMESTAMP-interval '30 seconds'))),0)>=t.routing_capacity_max THEN 'full'
 ELSE 'active' END AS effective_status,
s.routing_health,t.routing_health,t.routing_state,t.routing_players_online,t.routing_capacity_max,t.routing_accepting,
t.runtime_id,t.runtime_epoch,t.routing_revision,
COALESCE(e.last_seen_at,LEAST(s.routing_observed_at,t.routing_observed_at)),COALESCE(e.created_at,GREATEST(s.created_at,t.created_at))
FROM server_bridge_nodes_v2 s
JOIN server_bridge_nodes_v2 t ON t.project_id=s.project_id
 AND (s.profile_id='' OR t.profile_id='' OR t.profile_id=s.profile_id)
 AND t.kind IN ('bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge')
LEFT JOIN server_bridge_topology_edges_v2 e ON e.source_node_id=s.id AND e.target_node_id=t.id
WHERE s.kind IN ('velocity','bungeecord','waterfall')
ORDER BY s.id,t.name,t.id
LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ServerBridgeTopologyEdge{}
	for rows.Next() {
		var e model.ServerBridgeTopologyEdge
		if err := rows.Scan(&e.SourceNodeID, &e.TargetNodeID, &e.BackendName, &e.ProjectID, &e.ProfileID, &e.Status,
			&e.SourceHealth, &e.TargetHealth, &e.TargetState, &e.TargetPlayers, &e.TargetCapacity, &e.AcceptingConnections,
			&e.TargetRuntimeID, &e.TargetRuntimeEpoch, &e.RoutingRevision, &e.LastSeenAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *SQLRepository) MaintainServerBridge(ctx context.Context, now time.Time) (model.ServerBridgeMaintenanceResult, error) {
	result := model.ServerBridgeMaintenanceResult{CompletedAt: now.UTC()}
	if err := r.check(); err != nil {
		return result, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(1409,149)`).Scan(&locked); err != nil {
		return result, err
	}
	if !locked {
		if err = tx.Commit(); err != nil {
			return result, err
		}
		return result, nil
	}
	result.LeaseAcquired = true
	// Every maintenance batch locks only the rows it will mutate. The advisory
	// lock prevents duplicate NeverLauncher maintenance work across replicas;
	// SKIP LOCKED additionally avoids waiting behind normal ticket/handoff writes.
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_node_nonces_v2 n USING (SELECT node_id,nonce_hash FROM server_bridge_node_nonces_v2 WHERE expires_at <= $1 ORDER BY expires_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE n.node_id=q.node_id AND n.nonce_hash=q.nonce_hash`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.ExpiredNoncesDeleted, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `UPDATE server_bridge_join_tickets_v2 j SET status='invalidated',invalidated_at=$1 FROM (SELECT id FROM server_bridge_join_tickets_v2 WHERE status='active' AND expires_at <= $1 ORDER BY expires_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE j.id=q.id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.JoinTicketsInvalidated, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 h SET status='expired',invalidated_at=$1 FROM (SELECT id FROM server_bridge_handoffs_v2 WHERE status='active' AND expires_at <= $1 ORDER BY expires_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE h.id=q.id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.HandoffsExpired, _ = res.RowsAffected()
	}
	// A gameplay lifecycle may outlive its short-lived join/handoff rows, but it
	// must never outlive the Never session or the exact proxy/backend runtime it
	// was bound to. Invalidate under the same maintenance transaction so the
	// existing durable Control API can fan out player.kick to every live side.
	staleRows, queryErr := tx.QueryContext(ctx, `SELECT p.correlation_id FROM server_bridge_player_sessions_v3 p
		WHERE p.status='active' AND (
			NOT EXISTS (SELECT 1 FROM auth_sessions a WHERE a.id=p.never_session_id AND a.user_id=p.user_id AND a.status='active' AND a.expires_at>$1 AND a.binding_epoch=p.binding_epoch)
			OR (p.proxy_node_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM server_bridge_nodes_v2 n WHERE n.id=p.proxy_node_id AND n.status='active' AND n.runtime_id=p.proxy_runtime_id AND n.runtime_epoch=p.proxy_runtime_epoch))
			OR (p.backend_node_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM server_bridge_nodes_v2 n WHERE n.id=p.backend_node_id AND n.status='active' AND n.runtime_id=p.backend_runtime_id AND n.runtime_epoch=p.backend_runtime_epoch))
		)
		ORDER BY p.updated_at LIMIT 1000 FOR UPDATE OF p SKIP LOCKED`, now.UTC())
	if queryErr != nil {
		return result, queryErr
	}
	staleCorrelations := make([]string, 0, 64)
	for staleRows.Next() {
		var correlationID string
		if scanErr := staleRows.Scan(&correlationID); scanErr != nil {
			staleRows.Close()
			return result, scanErr
		}
		staleCorrelations = append(staleCorrelations, correlationID)
	}
	if queryErr = staleRows.Close(); queryErr != nil {
		return result, queryErr
	}
	for _, correlationID := range staleCorrelations {
		invalidated, invalidateErr := r.invalidatePlayerSessionRowTx0197(ctx, tx, correlationID, "session-revoked-or-runtime-replaced", now)
		if invalidateErr != nil {
			return result, invalidateErr
		}
		if invalidated {
			result.PlayerSessionsInvalidated++
		}
	}
	if res, execErr := tx.ExecContext(ctx, `UPDATE server_bridge_topology_edges_v2 e SET status='disabled' FROM (SELECT source_node_id,target_node_id FROM server_bridge_topology_edges_v2 WHERE status='active' AND last_seen_at <= $1::timestamptz - interval '5 minutes' ORDER BY last_seen_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE e.source_node_id=q.source_node_id AND e.target_node_id=q.target_node_id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.TopologyEdgesDisabled, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_topology_edges_v2 e USING (SELECT source_node_id,target_node_id FROM server_bridge_topology_edges_v2 WHERE status='disabled' AND last_seen_at <= $1::timestamptz - interval '30 minutes' ORDER BY last_seen_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE e.source_node_id=q.source_node_id AND e.target_node_id=q.target_node_id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.TopologyEdgesPurged, _ = res.RowsAffected()
	}
	// Terminal transient rows are operational evidence, not permanent audit
	// records. Keep recent rows for diagnostics, but cap unbounded growth. A
	// consumed join remains available while its auth session is active because it
	// is the source proof for later proxy -> backend handoffs.
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_join_tickets_v2 j USING (SELECT j2.id FROM server_bridge_join_tickets_v2 j2 LEFT JOIN auth_sessions a ON a.id=j2.session_id WHERE ((j2.status='consumed' AND COALESCE(j2.consumed_at,j2.expires_at) <= $1::timestamptz - interval '1 hour' AND (a.id IS NULL OR a.status<>'active' OR a.expires_at <= $1::timestamptz)) OR (j2.status IN ('invalidated','replaced') AND COALESCE(j2.invalidated_at,j2.expires_at) <= $1::timestamptz - interval '1 hour')) ORDER BY COALESCE(j2.consumed_at,j2.invalidated_at,j2.expires_at) LIMIT 5000 FOR UPDATE OF j2 SKIP LOCKED) q WHERE j.id=q.id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.TerminalJoinTicketsPurged, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_handoffs_v2 h USING (SELECT id FROM server_bridge_handoffs_v2 WHERE status IN ('consumed','replaced','invalidated','expired') AND COALESCE(consumed_at,invalidated_at,expires_at) <= $1::timestamptz - interval '1 hour' ORDER BY COALESCE(consumed_at,invalidated_at,expires_at) LIMIT 5000 FOR UPDATE SKIP LOCKED) q WHERE h.id=q.id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.TerminalHandoffsPurged, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_telemetry_samples_v3 t USING (SELECT sample_id FROM server_bridge_telemetry_samples_v3 WHERE sampled_at <= $1::timestamptz - interval '7 days' ORDER BY sampled_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE t.sample_id=q.sample_id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.TelemetrySamplesPurged, _ = res.RowsAffected()
	}
	// Raw delivery rows are retained for bounded diagnostics only. Permanent event
	// evidence lives in audit_events, which is written in the same transaction as
	// the ACK cursor. Keep cursor rows so a reconnect cannot reuse an old sequence.
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_events_v3 e USING (SELECT server_id,runtime_epoch,sequence FROM server_bridge_events_v3 WHERE received_at <= $1::timestamptz - interval '30 days' ORDER BY received_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE e.server_id=q.server_id AND e.runtime_epoch=q.runtime_epoch AND e.sequence=q.sequence`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.EventStreamRowsPurged, _ = res.RowsAffected()
	}
	// Control commands are transient delivery state. Permanent evidence remains in
	// audit_events; retain terminal/expired rows for 30 days for diagnostics.
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_control_commands_v3 c USING (SELECT id FROM server_bridge_control_commands_v3 WHERE status IN ('succeeded','failed','unsupported','indeterminate','expired') AND updated_at <= $1::timestamptz - interval '30 days' ORDER BY updated_at LIMIT 10000 FOR UPDATE SKIP LOCKED) q WHERE c.id=q.id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.ControlCommandsPurged, _ = res.RowsAffected()
	}
	if res, execErr := tx.ExecContext(ctx, `DELETE FROM server_bridge_player_sessions_v3 p USING (SELECT correlation_id FROM server_bridge_player_sessions_v3 WHERE status IN ('invalidated','disconnected','expired') AND updated_at <= $1::timestamptz - interval '30 days' ORDER BY updated_at LIMIT 5000 FOR UPDATE SKIP LOCKED) q WHERE p.correlation_id=q.correlation_id`, now.UTC()); execErr != nil {
		return result, execErr
	} else {
		result.PlayerSessionsPurged, _ = res.RowsAffected()
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (r *SQLRepository) ServerBridgeHAStatus(ctx context.Context, now time.Time) (model.ServerBridgeHAStatus, error) {
	status := model.ServerBridgeHAStatus{ObservedAt: now.UTC(), FreshnessSeconds: int(serverBridgeFreshness0149 / time.Second)}
	if err := r.check(); err != nil {
		return status, err
	}
	row := r.db.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM server_bridge_nodes_v2),
 (SELECT count(*) FROM server_bridge_nodes_v2 WHERE status='active'),
 (SELECT count(*) FROM server_bridge_nodes_v2 WHERE status='active' AND last_heartbeat_at > $1::timestamptz - interval '2 minutes'),
 (SELECT count(*) FROM server_bridge_nodes_v2 WHERE status='active' AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= $1::timestamptz - interval '2 minutes')),
 (SELECT count(*) FROM server_bridge_topology_edges_v2 WHERE status='active'),
 (SELECT count(*) FROM server_bridge_topology_edges_v2 e JOIN server_bridge_nodes_v2 s ON s.id=e.source_node_id JOIN server_bridge_nodes_v2 t ON t.id=e.target_node_id WHERE e.status='active' AND e.last_seen_at > $1::timestamptz - interval '2 minutes' AND s.status='active' AND s.last_heartbeat_at > $1::timestamptz - interval '2 minutes' AND t.status='active' AND t.last_heartbeat_at > $1::timestamptz - interval '2 minutes'),
 (SELECT count(*) FROM server_bridge_topology_edges_v2 e JOIN server_bridge_nodes_v2 s ON s.id=e.source_node_id JOIN server_bridge_nodes_v2 t ON t.id=e.target_node_id WHERE e.status='active' AND NOT COALESCE((e.last_seen_at > $1::timestamptz - interval '2 minutes' AND s.status='active' AND s.last_heartbeat_at > $1::timestamptz - interval '2 minutes' AND t.status='active' AND t.last_heartbeat_at > $1::timestamptz - interval '2 minutes'),FALSE)),
 (SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active' AND expires_at>$1::timestamptz),
 (SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active' AND expires_at<=$1::timestamptz),
 (SELECT count(*) FROM server_bridge_handoffs_v2 WHERE status='active' AND expires_at>$1::timestamptz),
 (SELECT count(*) FROM server_bridge_handoffs_v2 WHERE status='active' AND expires_at<=$1::timestamptz),
 (SELECT count(*) FROM server_bridge_node_nonces_v2 WHERE expires_at<=$1::timestamptz)`, now.UTC())
	if err := row.Scan(&status.NodesTotal, &status.NodesActive, &status.NodesFresh, &status.NodesStale, &status.TopologyActive, &status.TopologyFresh, &status.TopologyStale, &status.ActiveJoinTickets, &status.ExpiredJoinBacklog, &status.ActiveHandoffs, &status.ExpiredHandoffBacklog, &status.ExpiredNonceBacklog); err != nil {
		return status, err
	}
	return status, nil
}

func scanServerBridgeControl0195(row interface{ Scan(...any) error }) (model.ServerBridgeControlCommand, error) {
	var c model.ServerBridgeControlCommand
	var payloadRaw, resultRaw []byte
	var leaseUntil, completedAt sql.NullTime
	err := row.Scan(&c.ID, &c.ServerID, &c.RuntimeEpoch, &c.RuntimeID, &c.Type, &payloadRaw, &c.PayloadSHA256, &c.RequestDigest,
		&c.RequestedBy, &c.IdempotencyKey, &c.Status, &c.Attempt, &c.CreatedAt, &c.UpdatedAt, &c.ExpiresAt,
		&c.DeliverySequence, &c.LeaseOwner, &c.LeaseToken, &leaseUntil, &completedAt, &resultRaw, &c.Error)
	if err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	if len(payloadRaw) > 0 {
		if err := json.Unmarshal(payloadRaw, &c.Payload); err != nil {
			return model.ServerBridgeControlCommand{}, err
		}
	}
	if c.Payload == nil {
		c.Payload = map[string]string{}
	}
	if len(resultRaw) > 0 {
		if err := json.Unmarshal(resultRaw, &c.Result); err != nil {
			return model.ServerBridgeControlCommand{}, err
		}
	}
	if c.Result == nil {
		c.Result = map[string]string{}
	}
	if leaseUntil.Valid {
		c.LeaseUntil = leaseUntil.Time
	}
	if completedAt.Valid {
		c.CompletedAt = completedAt.Time
	}
	return c, nil
}

const serverBridgeControlSelect0195 = `SELECT id,server_id,runtime_epoch,runtime_id,command_type,payload,payload_sha256,request_digest,requested_by,idempotency_key,status,attempt,created_at,updated_at,expires_at,delivery_sequence,lease_owner,lease_token,lease_until,completed_at,result,error FROM server_bridge_control_commands_v3`

// CreateServerBridgeControlCommand is exactly-once at admission per (server, actor, idempotency key).
// Reuse with the same canonical request returns the original command; reuse with a different
// digest is rejected on every API replica by the PostgreSQL unique key + advisory lock.
func (r *SQLRepository) CreateServerBridgeControlCommand(ctx context.Context, c model.ServerBridgeControlCommand, now time.Time) (model.ServerBridgeControlCommand, bool, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	if c.ID == "" || c.ServerID == "" || c.RuntimeEpoch < 1 || len(c.RuntimeID) != 64 || c.Type == "" || len(c.PayloadSHA256) != 64 || len(c.RequestDigest) != 64 || c.RequestedBy == "" || len(c.IdempotencyKey) < 8 || c.ExpiresAt.Before(now) {
		return model.ServerBridgeControlCommand{}, false, fmt.Errorf("%w: invalid control command", ErrConflict)
	}
	payload, err := json.Marshal(c.Payload)
	if err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(195, hashtext($1 || ':' || $2 || ':' || $3))`, c.ServerID, c.RequestedBy, c.IdempotencyKey); err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	var status, activeRuntime string
	var activeEpoch int64
	if err = tx.QueryRowContext(ctx, `SELECT status,runtime_id,runtime_epoch FROM server_bridge_nodes_v2 WHERE id=$1 FOR SHARE`, c.ServerID).Scan(&status, &activeRuntime, &activeEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeControlCommand{}, false, ErrNotFound
		}
		return model.ServerBridgeControlCommand{}, false, err
	}
	if status != "active" || activeEpoch != c.RuntimeEpoch || !strings.EqualFold(strings.TrimSpace(activeRuntime), c.RuntimeID) {
		return model.ServerBridgeControlCommand{}, false, fmt.Errorf("%w: control runtime is not active", ErrConflict)
	}
	if existing, scanErr := scanServerBridgeControl0195(tx.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE server_id=$1 AND requested_by=$2 AND idempotency_key=$3`, c.ServerID, c.RequestedBy, c.IdempotencyKey)); scanErr == nil {
		if !strings.EqualFold(existing.RequestDigest, c.RequestDigest) {
			return model.ServerBridgeControlCommand{}, false, fmt.Errorf("%w: idempotency key reused with different request", ErrConflict)
		}
		return existing, true, nil
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return model.ServerBridgeControlCommand{}, false, scanErr
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_control_commands_v3(id,server_id,runtime_epoch,runtime_id,command_type,payload,payload_sha256,request_digest,requested_by,idempotency_key,status,attempt,created_at,updated_at,expires_at,result,error) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,'pending',0,$11,$11,$12,'{}'::jsonb,'')`, c.ID, c.ServerID, c.RuntimeEpoch, c.RuntimeID, c.Type, string(payload), c.PayloadSHA256, c.RequestDigest, c.RequestedBy, c.IdempotencyKey, now.UTC(), c.ExpiresAt.UTC())
	if err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,$3,$4,'','ServerBridge Control API',$5) ON CONFLICT(id) DO NOTHING`, "serverbridge-control-queued-"+c.ID, c.RequestedBy, "serverbridge:control:queued:"+c.Type, c.ServerID+":"+c.ID, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeControlCommand{}, false, err
	}
	created, err := scanServerBridgeControl0195(r.db.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE id=$1`, c.ID))
	return created, false, err
}

// LeaseServerBridgeControlCommand provides a fenced, resumable command channel. leaseOwner is
// the bridge channel identity and survives Backend endpoint failover; leaseToken fences stale
// deliveries. A reconnect from the same owner receives its still-live lease instead of causing
// a second delivery attempt. resumeAfter is the highest locally acknowledged delivery sequence.
func (r *SQLRepository) LeaseServerBridgeControlCommand(ctx context.Context, serverID string, runtimeEpoch int64, runtimeID, leaseOwner, leaseToken string, resumeAfter int64, now time.Time, lease time.Duration) (model.ServerBridgeControlCommand, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	leaseOwner = strings.TrimSpace(leaseOwner)
	leaseToken = strings.TrimSpace(leaseToken)
	if len(leaseOwner) < 16 || len(leaseOwner) > 128 || len(leaseToken) < 16 || len(leaseToken) > 160 || resumeAfter < 0 {
		return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: invalid control lease identity", ErrConflict)
	}
	if lease < 5*time.Second {
		lease = 5 * time.Second
	}
	if lease > 2*time.Minute {
		lease = 2 * time.Minute
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	defer tx.Rollback()
	var status, currentRuntime string
	var currentEpoch int64
	if err = tx.QueryRowContext(ctx, `SELECT status,runtime_id,runtime_epoch FROM server_bridge_nodes_v2 WHERE id=$1 FOR SHARE`, serverID).Scan(&status, &currentRuntime, &currentEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeControlCommand{}, ErrNotFound
		}
		return model.ServerBridgeControlCommand{}, err
	}
	if status != "active" || currentEpoch != runtimeEpoch || !strings.EqualFold(strings.TrimSpace(currentRuntime), runtimeID) {
		return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: control runtime is not active", ErrConflict)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_control_commands_v3 SET status='expired',updated_at=$2,completed_at=$2,error='expired before delivery',lease_until=NULL WHERE server_id=$1 AND status IN ('pending','leased') AND expires_at <= $2`, serverID, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	// HTTP response loss or Backend endpoint failover: resume the exact live lease for this channel.
	if existing, scanErr := scanServerBridgeControl0195(tx.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE server_id=$1 AND runtime_epoch=$2 AND runtime_id=$3 AND status='leased' AND lease_owner=$4 AND lease_until>$5 AND delivery_sequence>$6 ORDER BY delivery_sequence LIMIT 1 FOR UPDATE`, serverID, runtimeEpoch, runtimeID, leaseOwner, now.UTC(), resumeAfter)); scanErr == nil {
		if err = tx.Commit(); err != nil {
			return model.ServerBridgeControlCommand{}, err
		}
		return existing, nil
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return model.ServerBridgeControlCommand{}, scanErr
	}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM server_bridge_control_commands_v3 WHERE server_id=$1 AND runtime_epoch=$2 AND runtime_id=$3 AND delivery_sequence>$4 AND expires_at>$5 AND (status='pending' OR (status='leased' AND lease_until<=$5)) ORDER BY delivery_sequence FOR UPDATE SKIP LOCKED LIMIT 1`, serverID, runtimeEpoch, runtimeID, resumeAfter, now.UTC()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeControlCommand{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	leaseUntil := now.Add(lease).UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_control_commands_v3 SET status='leased',attempt=attempt+1,lease_owner=$2,lease_token=$3,lease_until=$4,updated_at=$5 WHERE id=$1`, id, leaseOwner, leaseToken, leaseUntil, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,'serverbridge:control:delivered',$3,'','ServerBridge Control API',$4) ON CONFLICT(id) DO NOTHING`, `serverbridge-control-delivered-`+id+`-`+leaseToken, serverID, serverID+":"+id, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	return scanServerBridgeControl0195(r.db.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE id=$1`, id))
}

// CompleteServerBridgeControlCommand is an idempotent fenced commit. Only the channel and lease
// token that received the command can complete it. The token is retained after completion so a
// retry routed to a different Backend replica receives the same durable result.
func (r *SQLRepository) CompleteServerBridgeControlCommand(ctx context.Context, serverID string, runtimeEpoch int64, runtimeID, commandID, leaseOwner, leaseToken string, deliverySequence int64, status string, result map[string]string, failure string, now time.Time) (model.ServerBridgeControlCommand, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	allowed := map[string]bool{"succeeded": true, "failed": true, "unsupported": true, "indeterminate": true}
	if !allowed[status] || len(strings.TrimSpace(leaseOwner)) < 16 || len(strings.TrimSpace(leaseToken)) < 16 || deliverySequence < 1 {
		return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: invalid control result", ErrConflict)
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	defer tx.Rollback()
	current, err := scanServerBridgeControl0195(tx.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE id=$1 FOR UPDATE`, commandID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ServerBridgeControlCommand{}, ErrNotFound
		}
		return model.ServerBridgeControlCommand{}, err
	}
	if current.ServerID != serverID || current.RuntimeEpoch != runtimeEpoch || !strings.EqualFold(current.RuntimeID, runtimeID) || current.DeliverySequence != deliverySequence || current.LeaseOwner != leaseOwner || current.LeaseToken != leaseToken {
		return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: control acknowledgement lease mismatch", ErrConflict)
	}
	if current.Status == "succeeded" || current.Status == "failed" || current.Status == "unsupported" || current.Status == "indeterminate" {
		if current.Status != status || !serverBridgeControlStringMapEqual0195(current.Result, result) || current.Error != failure {
			return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: conflicting control acknowledgement", ErrConflict)
		}
		return current, nil
	}
	if current.Status != "leased" || !current.LeaseUntil.After(now) {
		return model.ServerBridgeControlCommand{}, fmt.Errorf("%w: control command lease expired", ErrConflict)
	}
	if len(failure) > 1024 {
		failure = failure[:1024]
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_control_commands_v3 SET status=$2,result=$3::jsonb,error=$4,completed_at=$5,updated_at=$5,lease_until=NULL WHERE id=$1`, commandID, status, string(resultJSON), failure, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,$3,$4,'','ServerBridge Control API',$5) ON CONFLICT(id) DO NOTHING`, `serverbridge-control-complete-`+commandID, serverID, "serverbridge:control:"+status, current.Type+":"+commandID, now.UTC()); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	return scanServerBridgeControl0195(r.db.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE id=$1`, commandID))
}

func serverBridgeControlStringMapEqual0195(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (r *SQLRepository) GetServerBridgeControlCommand(ctx context.Context, serverID, commandID string) (model.ServerBridgeControlCommand, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeControlCommand{}, err
	}
	c, err := scanServerBridgeControl0195(r.db.QueryRowContext(ctx, serverBridgeControlSelect0195+` WHERE server_id=$1 AND id=$2`, serverID, commandID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeControlCommand{}, ErrNotFound
	}
	return c, err
}
