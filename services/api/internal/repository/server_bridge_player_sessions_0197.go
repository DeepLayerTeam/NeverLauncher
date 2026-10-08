package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const serverBridgePlayerSessionControlActor0197 = "serverbridge-player-session"

func validPlayerCorrelation0197(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isProxyBridgeKind0197(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "velocity", "bungeecord", "waterfall":
		return true
	default:
		return false
	}
}

func (r *SQLRepository) queuePlayerKickTx0197(ctx context.Context, tx *sql.Tx, correlationID, username, nodeID, runtimeID string, runtimeEpoch int64, reason string, now time.Time) error {
	nodeID = strings.TrimSpace(nodeID)
	runtimeID = strings.ToLower(strings.TrimSpace(runtimeID))
	if nodeID == "" || runtimeEpoch < 1 || len(runtimeID) != 64 || strings.TrimSpace(username) == "" {
		return nil
	}
	payload := map[string]string{"username": strings.TrimSpace(username), "reason": strings.TrimSpace(reason)}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	payloadDigest := sha256.Sum256(payloadJSON)
	payloadSHA := hex.EncodeToString(payloadDigest[:])
	keyMaterial := strings.Join([]string{correlationID, nodeID, runtimeID, fmt.Sprint(runtimeEpoch), reason}, "\n")
	keyDigest := sha256.Sum256([]byte(keyMaterial))
	keyHex := hex.EncodeToString(keyDigest[:])
	commandID := "ctlps_" + keyHex[:48]
	idempotency := "player-session-" + keyHex[:40]
	requestMaterial := strings.Join([]string{nodeID, fmt.Sprint(runtimeEpoch), runtimeID, "player.kick", payloadSHA, serverBridgePlayerSessionControlActor0197, idempotency}, "\n")
	requestDigest := sha256.Sum256([]byte(requestMaterial))
	expiresAt := now.UTC().Add(2 * time.Minute)
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_control_commands_v3(id,server_id,runtime_epoch,runtime_id,command_type,payload,payload_sha256,request_digest,requested_by,idempotency_key,status,attempt,created_at,updated_at,expires_at,result,error)
		VALUES($1,$2,$3,$4,'player.kick',$5::jsonb,$6,$7,$8,$9,'pending',0,$10,$10,$11,'{}'::jsonb,'')
		ON CONFLICT(server_id,requested_by,idempotency_key) DO NOTHING`, commandID, nodeID, runtimeEpoch, runtimeID, string(payloadJSON), payloadSHA, hex.EncodeToString(requestDigest[:]), serverBridgePlayerSessionControlActor0197, idempotency, now.UTC(), expiresAt)
	if err != nil {
		return err
	}
	auditID := "serverbridge-player-disconnect-" + keyHex[:48]
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,'serverbridge:player-session:disconnect-queued',$3,'','Player Session Integration 3',$4) ON CONFLICT(id) DO NOTHING`, auditID, serverBridgePlayerSessionControlActor0197, nodeID+":"+correlationID, now.UTC())
	return err
}

func (r *SQLRepository) invalidatePlayerSessionRowTx0197(ctx context.Context, tx *sql.Tx, correlationID, reason string, now time.Time) (bool, error) {
	var username, status, proxyNode, proxyRuntime, backendNode, backendRuntime string
	var proxyEpoch, backendEpoch int64
	err := tx.QueryRowContext(ctx, `SELECT username,status,COALESCE(proxy_node_id,''),proxy_runtime_id,proxy_runtime_epoch,COALESCE(backend_node_id,''),backend_runtime_id,backend_runtime_epoch FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1 FOR UPDATE`, correlationID).
		Scan(&username, &status, &proxyNode, &proxyRuntime, &proxyEpoch, &backendNode, &backendRuntime, &backendEpoch)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if status != "active" {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET status='invalidated',recheck_required=FALSE,invalidated_at=$2,invalidated_reason=$3,updated_at=$2 WHERE correlation_id=$1 AND status='active'`, correlationID, now.UTC(), strings.TrimSpace(reason)); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_transfers_v3 SET status='invalidated' WHERE correlation_id=$1 AND status='issued'`, correlationID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE session_correlation_id=$1 AND status='active'`, correlationID, now.UTC()); err != nil {
		return false, err
	}
	kickReason := "NeverLauncher session invalidated"
	if strings.TrimSpace(reason) != "" {
		kickReason += ": " + strings.TrimSpace(reason)
	}
	if err = r.queuePlayerKickTx0197(ctx, tx, correlationID, username, proxyNode, proxyRuntime, proxyEpoch, kickReason, now); err != nil {
		return false, err
	}
	if backendNode != proxyNode || backendRuntime != proxyRuntime || backendEpoch != proxyEpoch {
		if err = r.queuePlayerKickTx0197(ctx, tx, correlationID, username, backendNode, backendRuntime, backendEpoch, kickReason, now); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (r *SQLRepository) activatePlayerSessionTx0197(ctx context.Context, tx *sql.Tx, join model.ServerBridgeJoinTicket, redemption model.ServerBridgeJoinRedemption, now time.Time) error {
	correlationID := strings.ToLower(strings.TrimSpace(join.SessionCorrelationID))
	if correlationID == "" { // pre-0.19.7 rolling-upgrade ticket
		return nil
	}
	if !validPlayerCorrelation0197(correlationID) {
		return fmt.Errorf("%w: недопустимый игрок сессия корреляция", ErrConflict)
	}
	if redemption.SessionCorrelationID != "" && !strings.EqualFold(redemption.SessionCorrelationID, correlationID) {
		return fmt.Errorf("%w: игрок сессия корреляция несоответствие", ErrConflict)
	}
	var nodeKind, runtimeID string
	var runtimeEpoch int64
	if err := tx.QueryRowContext(ctx, `SELECT kind,runtime_id,runtime_epoch FROM server_bridge_nodes_v2 WHERE id=$1 AND status='active' FOR SHARE`, redemption.NodeID).Scan(&nodeKind, &runtimeID, &runtimeEpoch); err != nil {
		return err
	}
	if len(runtimeID) != 64 || runtimeEpoch < 1 {
		// Протокол v2 узлы predate процесс среда выполнения идентичность. Сохранять поэтапный обновление
		// эксплуатационный без fabricating unverifiable жизненный цикл привязка.
		if join.ProtocolVersion < 3 {
			return nil
		}
		return fmt.Errorf("%w: игрок сессия среда выполнения недоступный", ErrConflict)
	}
	lockKey := join.SessionID + ":" + join.UUID
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1970, hashtext($1))`, lockKey); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT correlation_id FROM server_bridge_player_sessions_v3 WHERE status='active' AND correlation_id<>$1 AND ((never_session_id=$2 AND player_uuid=$3) OR ($4<>'' AND minecraft_session_id=$4)) FOR UPDATE`, correlationID, join.SessionID, join.UUID, join.MinecraftSessionID)
	if err != nil {
		return err
	}
	var old []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		old = append(old, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range old {
		if _, err := r.invalidatePlayerSessionRowTx0197(ctx, tx, id, "session-clone-replaced", now); err != nil {
			return err
		}
	}
	proxyNode, proxyRuntime, backendNode, backendRuntime := "", "", "", ""
	var proxyEpoch, backendEpoch int64
	if isProxyBridgeKind0197(nodeKind) {
		proxyNode, proxyRuntime, proxyEpoch = redemption.NodeID, strings.ToLower(runtimeID), runtimeEpoch
	} else {
		backendNode, backendRuntime, backendEpoch = redemption.NodeID, strings.ToLower(runtimeID), runtimeEpoch
	}
	verifiedAt := redemption.VerifiedAt
	if verifiedAt.IsZero() {
		verifiedAt = now.UTC()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO server_bridge_player_sessions_v3(correlation_id,player_uuid,username,username_normalized,user_id,never_session_id,minecraft_session_id,trusted_device_id,binding_epoch,project_id,profile_id,channel,status,proxy_node_id,proxy_runtime_id,proxy_runtime_epoch,backend_node_id,backend_runtime_id,backend_runtime_epoch,transfer_sequence,recheck_required,trust_reason,integrity_reason,last_verified_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'active',NULLIF($13,''),$14,$15,NULLIF($16,''),$17,$18,0,FALSE,$19,$20,$21,$22,$22)
		ON CONFLICT(correlation_id) DO UPDATE SET status='active',proxy_node_id=CASE WHEN EXCLUDED.proxy_node_id IS NOT NULL THEN EXCLUDED.proxy_node_id ELSE server_bridge_player_sessions_v3.proxy_node_id END,proxy_runtime_id=CASE WHEN EXCLUDED.proxy_node_id IS NOT NULL THEN EXCLUDED.proxy_runtime_id ELSE server_bridge_player_sessions_v3.proxy_runtime_id END,proxy_runtime_epoch=CASE WHEN EXCLUDED.proxy_node_id IS NOT NULL THEN EXCLUDED.proxy_runtime_epoch ELSE server_bridge_player_sessions_v3.proxy_runtime_epoch END,backend_node_id=CASE WHEN EXCLUDED.backend_node_id IS NOT NULL THEN EXCLUDED.backend_node_id ELSE server_bridge_player_sessions_v3.backend_node_id END,backend_runtime_id=CASE WHEN EXCLUDED.backend_node_id IS NOT NULL THEN EXCLUDED.backend_runtime_id ELSE server_bridge_player_sessions_v3.backend_runtime_id END,backend_runtime_epoch=CASE WHEN EXCLUDED.backend_node_id IS NOT NULL THEN EXCLUDED.backend_runtime_epoch ELSE server_bridge_player_sessions_v3.backend_runtime_epoch END,recheck_required=FALSE,trust_reason=EXCLUDED.trust_reason,integrity_reason=EXCLUDED.integrity_reason,last_verified_at=EXCLUDED.last_verified_at,updated_at=EXCLUDED.updated_at`,
		correlationID, join.UUID, join.Username, join.UsernameNormalized, join.UserID, join.SessionID, join.MinecraftSessionID, join.TrustedDeviceID, join.BindingEpoch, join.ProjectID, join.ProfileID, join.Channel,
		proxyNode, proxyRuntime, proxyEpoch, backendNode, backendRuntime, backendEpoch, redemption.TrustReason, redemption.IntegrityReason, verifiedAt.UTC(), now.UTC())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,'serverbridge:player-session:activated',$3,'','Player Session Integration 3',$4) ON CONFLICT(id) DO NOTHING`, "serverbridge-player-activate-"+correlationID, redemption.NodeID, correlationID+":"+join.Username, now.UTC())
	return err
}

func (r *SQLRepository) issuePlayerTransferTx0197(ctx context.Context, tx *sql.Tx, h *model.ServerBridgeHandoff, expectedCorrelation string, now time.Time) error {
	if h == nil || strings.TrimSpace(h.SessionCorrelationID) == "" {
		return nil
	}
	correlationID := strings.ToLower(strings.TrimSpace(h.SessionCorrelationID))
	if expectedCorrelation != "" && !strings.EqualFold(expectedCorrelation, correlationID) {
		return fmt.Errorf("%w: сессия корреляция доказательство несоответствие", ErrConflict)
	}
	var status, proxyNode, proxyRuntime string
	var proxyEpoch, sequence int64
	err := tx.QueryRowContext(ctx, `SELECT status,COALESCE(proxy_node_id,''),proxy_runtime_id,proxy_runtime_epoch,transfer_sequence FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1 FOR UPDATE`, correlationID).
		Scan(&status, &proxyNode, &proxyRuntime, &proxyEpoch, &sequence)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: correlated игрок сессия не активный", ErrConflict)
		}
		return err
	}
	if status != "active" || proxyNode != h.SourceNodeID || (h.SourceRuntimeID != "" && (!strings.EqualFold(proxyRuntime, h.SourceRuntimeID) || proxyEpoch != h.SourceRuntimeEpoch)) {
		return fmt.Errorf("%w: исходник прокси делает не собственный correlated сессия", ErrConflict)
	}
	sequence++
	h.TransferSequence = sequence
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET transfer_sequence=$2,recheck_required=TRUE,updated_at=$3 WHERE correlation_id=$1 AND status='active'`, correlationID, sequence, now.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_transfers_v3 SET status='superseded' WHERE correlation_id=$1 AND status='issued'`, correlationID); err != nil {
		return err
	}
	return nil
}

func (r *SQLRepository) recordPlayerTransferTx0197(ctx context.Context, tx *sql.Tx, h model.ServerBridgeHandoff, now time.Time) error {
	if strings.TrimSpace(h.SessionCorrelationID) == "" || h.TransferSequence < 1 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO server_bridge_player_transfers_v3(correlation_id,sequence,handoff_id,source_node_id,target_node_id,source_runtime_id,source_runtime_epoch,target_runtime_id,target_runtime_epoch,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'issued',$10)`, strings.ToLower(h.SessionCorrelationID), h.TransferSequence, h.ID, h.SourceNodeID, h.TargetNodeID, h.SourceRuntimeID, h.SourceRuntimeEpoch, h.TargetRuntimeID, h.TargetRuntimeEpoch, now.UTC())
	return err
}

func (r *SQLRepository) consumePlayerTransferTx0197(ctx context.Context, tx *sql.Tx, h model.ServerBridgeHandoff, redemption model.ServerBridgeJoinRedemption, now time.Time) error {
	correlationID := strings.ToLower(strings.TrimSpace(h.SessionCorrelationID))
	if correlationID == "" {
		return nil
	}
	if redemption.SessionCorrelationID != "" && !strings.EqualFold(redemption.SessionCorrelationID, correlationID) {
		return fmt.Errorf("%w: игрок переход корреляция несоответствие", ErrConflict)
	}
	var status, username, proxyNode, oldBackend, oldBackendRuntime string
	var sequence, oldBackendEpoch int64
	err := tx.QueryRowContext(ctx, `SELECT status,username,COALESCE(proxy_node_id,''),transfer_sequence,COALESCE(backend_node_id,''),backend_runtime_id,backend_runtime_epoch FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1 FOR UPDATE`, correlationID).
		Scan(&status, &username, &proxyNode, &sequence, &oldBackend, &oldBackendRuntime, &oldBackendEpoch)
	if err != nil {
		return err
	}
	if status != "active" || proxyNode != h.SourceNodeID || sequence != h.TransferSequence || h.TransferSequence < 1 {
		return fmt.Errorf("%w: устаревший или cloned игрок переход", ErrConflict)
	}
	var transferStatus string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM server_bridge_player_transfers_v3 WHERE correlation_id=$1 AND sequence=$2 AND handoff_id=$3 FOR UPDATE`, correlationID, h.TransferSequence, h.ID).Scan(&transferStatus); err != nil {
		return err
	}
	if transferStatus != "issued" {
		return fmt.Errorf("%w: игрок переход уже использованный", ErrConflict)
	}
	verifiedAt := redemption.VerifiedAt
	if verifiedAt.IsZero() {
		verifiedAt = now.UTC()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET backend_node_id=$2,backend_runtime_id=$3,backend_runtime_epoch=$4,recheck_required=FALSE,trust_reason=$5,integrity_reason=$6,last_verified_at=$7,updated_at=$8 WHERE correlation_id=$1 AND status='active'`, correlationID, h.TargetNodeID, strings.ToLower(h.TargetRuntimeID), h.TargetRuntimeEpoch, redemption.TrustReason, redemption.IntegrityReason, verifiedAt.UTC(), now.UTC()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_transfers_v3 SET status='consumed',consumed_at=$4 WHERE correlation_id=$1 AND sequence=$2 AND handoff_id=$3 AND status='issued'`, correlationID, h.TransferSequence, h.ID, now.UTC()); err != nil {
		return err
	}
	if oldBackend != "" && oldBackend != h.TargetNodeID {
		if err = r.queuePlayerKickTx0197(ctx, tx, correlationID, username, oldBackend, oldBackendRuntime, oldBackendEpoch, "NeverLauncher backend transfer completed", now); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,'serverbridge:player-session:transfer-consumed',$3,'','Player Session Integration 3',$4) ON CONFLICT(id) DO NOTHING`, fmt.Sprintf("serverbridge-player-transfer-%s-%d", correlationID, h.TransferSequence), h.TargetNodeID, correlationID+":"+h.SourceNodeID+"->"+h.TargetNodeID, now.UTC())
	return err
}

func (r *SQLRepository) invalidatePlayerSessionsBySessionTx0197(ctx context.Context, tx *sql.Tx, sessionID, serverID, reason string, now time.Time) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT correlation_id FROM server_bridge_player_sessions_v3 WHERE never_session_id=$1 AND status='active' AND ($2='' OR proxy_node_id=$2 OR backend_node_id=$2) FOR UPDATE`, sessionID, serverID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		ok, err := r.invalidatePlayerSessionRowTx0197(ctx, tx, id, reason, now)
		if err != nil {
			return count, err
		}
		if ok {
			count++
		}
	}
	return count, nil
}

func (r *SQLRepository) invalidatePlayerSessionsByUserTx0197(ctx context.Context, tx *sql.Tx, userID, reason string, now time.Time) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT correlation_id FROM server_bridge_player_sessions_v3 WHERE user_id=$1 AND status='active' FOR UPDATE`, userID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		ok, err := r.invalidatePlayerSessionRowTx0197(ctx, tx, id, reason, now)
		if err != nil {
			return count, err
		}
		if ok {
			count++
		}
	}
	return count, nil
}

func (r *SQLRepository) applyPlayerLifecycleEventTx0197(ctx context.Context, tx *sql.Tx, serverID string, event model.ServerBridgeEvent, now time.Time) error {
	if event.Type != "player.quit" && event.Type != "player.kick" {
		return nil
	}
	correlationID := strings.ToLower(strings.TrimSpace(event.Payload["sessionCorrelationId"]))
	if !validPlayerCorrelation0197(correlationID) {
		return nil // rolling-upgrade event without lifecycle correlation
	}
	var status, proxyNode, backendNode string
	err := tx.QueryRowContext(ctx, `SELECT status,COALESCE(proxy_node_id,''),COALESCE(backend_node_id,'') FROM server_bridge_player_sessions_v3 WHERE correlation_id=$1 FOR UPDATE`, correlationID).Scan(&status, &proxyNode, &backendNode)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return nil
	}
	if serverID == proxyNode {
		proxyNode = ""
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET proxy_node_id=NULL,proxy_runtime_id='',proxy_runtime_epoch=0,updated_at=$2 WHERE correlation_id=$1`, correlationID, now.UTC()); err != nil {
			return err
		}
	}
	if serverID == backendNode {
		backendNode = ""
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET backend_node_id=NULL,backend_runtime_id='',backend_runtime_epoch=0,updated_at=$2 WHERE correlation_id=$1`, correlationID, now.UTC()); err != nil {
			return err
		}
	}
	if proxyNode == "" && backendNode == "" {
		_, err = tx.ExecContext(ctx, `UPDATE server_bridge_player_sessions_v3 SET status='disconnected',updated_at=$2 WHERE correlation_id=$1 AND status='active'`, correlationID, now.UTC())
	}
	return err
}
