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

const serverBridgeRoutingFreshness0196 = 90 * time.Second

func (r *SQLRepository) SaveServerBridgeRoutingState(ctx context.Context, serverID string, runtimeEpoch int64, routing model.ServerBridgeRoutingSnapshot, now time.Time) (model.ServerBridgeRoutingSnapshot, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}
	serverID = strings.TrimSpace(serverID)
	routing.RuntimeID = strings.ToLower(strings.TrimSpace(routing.RuntimeID))
	routing.Digest = strings.ToLower(strings.TrimSpace(routing.Digest))
	routing.Signature = strings.TrimSpace(routing.Signature)
	routing.State = strings.ToLower(strings.TrimSpace(routing.State))
	routing.Health = strings.ToLower(strings.TrimSpace(routing.Health))
	if serverID == "" || runtimeEpoch < 1 || len(routing.RuntimeID) != 64 || len(routing.Digest) != 64 || routing.Signature == "" {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("%w: invalid routing snapshot", ErrConflict)
	}
	observedAt := time.UnixMilli(routing.ObservedAtUnixMillis).UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1960, hashtext($1))`, serverID); err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}

	var status, currentRuntimeID, oldDigest string
	var currentRuntimeEpoch, oldRevision int64
	var oldObserved sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT status,runtime_id,runtime_epoch,routing_digest,routing_revision,routing_observed_at FROM server_bridge_nodes_v2 WHERE id=$1 FOR UPDATE`, serverID).
		Scan(&status, &currentRuntimeID, &currentRuntimeEpoch, &oldDigest, &oldRevision, &oldObserved)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeRoutingSnapshot{}, ErrNotFound
	}
	if err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}
	if status != "active" || currentRuntimeEpoch != runtimeEpoch || !strings.EqualFold(currentRuntimeID, routing.RuntimeID) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("%w: routing runtime is not active", ErrConflict)
	}
	if oldObserved.Valid && observedAt.Before(oldObserved.Time) {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("%w: stale routing snapshot", ErrConflict)
	}
	if oldObserved.Valid && observedAt.Equal(oldObserved.Time) {
		if strings.EqualFold(oldDigest, routing.Digest) {
			routing.Revision = oldRevision
			routing.ObservedAt = oldObserved.Time
			return routing, tx.Commit()
		}
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("%w: routing proof changed at same observation time", ErrConflict)
	}
	revision := oldRevision + 1
	if revision < 1 {
		revision = 1
	}
	res, err := tx.ExecContext(ctx, `UPDATE server_bridge_nodes_v2 SET routing_state=$4,routing_accepting=$5,routing_players_online=$6,routing_capacity_max=$7,routing_health=$8,routing_observed_at=$9,routing_revision=$10,routing_digest=$11,routing_signature=$12
        WHERE id=$1 AND runtime_epoch=$2 AND runtime_id=$3 AND status='active'`,
		serverID, runtimeEpoch, routing.RuntimeID, routing.State, routing.AcceptingConnections, routing.PlayersOnline, routing.CapacityMax, routing.Health, observedAt, revision, routing.Digest, routing.Signature)
	if err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.ServerBridgeRoutingSnapshot{}, fmt.Errorf("%w: active runtime changed during routing update", ErrConflict)
	}
	// Once a backend stops accepting routes, invalidate outstanding handoffs now
	// instead of waiting for redemption. The captured target proof remains audit
	// evidence, while no stale credential can enter a draining/unhealthy server.
	if !routing.AcceptingConnections || routing.State != "ready" || routing.Health == "unhealthy" {
		if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE target_node_id=$1 AND status='active'`, serverID, now.UTC()); err != nil {
			return model.ServerBridgeRoutingSnapshot{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return model.ServerBridgeRoutingSnapshot{}, err
	}
	routing.Revision = revision
	routing.ObservedAt = observedAt
	return routing, nil
}

func (r *SQLRepository) ListServerBridgeAllowedBackends(ctx context.Context, sourceID string, now time.Time) ([]model.ServerBridgeRouteTarget, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	sourceID = strings.TrimSpace(sourceID)
	var sourceKind, sourceStatus, projectID, profileID, sourceState, sourceHealth string
	var sourceAccepting bool
	var sourceHeartbeat, sourceRoutingObserved sql.NullTime
	var sourceRuntimeEpoch int64
	var sourceRuntimeID string
	err := r.db.QueryRowContext(ctx, `SELECT kind,status,project_id,profile_id,routing_state,routing_health,routing_accepting,last_heartbeat_at,routing_observed_at,runtime_epoch,runtime_id FROM server_bridge_nodes_v2 WHERE id=$1`, sourceID).
		Scan(&sourceKind, &sourceStatus, &projectID, &profileID, &sourceState, &sourceHealth, &sourceAccepting, &sourceHeartbeat, &sourceRoutingObserved, &sourceRuntimeEpoch, &sourceRuntimeID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	freshAfter := now.UTC().Add(-serverBridgeRoutingFreshness0196)
	if sourceStatus != "active" || !isProxyBridgeKind0148(sourceKind) || sourceRuntimeEpoch < 1 || len(sourceRuntimeID) != 64 || !sourceHeartbeat.Valid || sourceHeartbeat.Time.Before(freshAfter) || !sourceRoutingObserved.Valid || sourceRoutingObserved.Time.Before(freshAfter) || sourceState != "ready" || !sourceAccepting || sourceHealth == "unhealthy" {
		return nil, fmt.Errorf("%w: source proxy is not routable", ErrConflict)
	}

	rows, err := r.db.QueryContext(ctx, `SELECT n.id,n.name,n.kind,n.project_id,n.profile_id,n.runtime_id,n.runtime_epoch,n.routing_health,n.routing_state,n.routing_players_online,n.routing_capacity_max,n.routing_revision,n.routing_digest,n.routing_observed_at,n.last_heartbeat_at,
        COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 h WHERE h.target_node_id=n.id AND ((h.status='active' AND h.expires_at>$4) OR (h.status='consumed' AND h.consumed_at>$4::timestamptz-interval '30 seconds'))),0) AS reserved
        FROM server_bridge_nodes_v2 n
        WHERE n.status='active' AND n.kind IN ('bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge')
          AND n.project_id=$1 AND ($2='' OR n.profile_id='' OR n.profile_id=$2)
          AND n.runtime_epoch>0 AND n.runtime_id ~ '^[0-9a-f]{64}$'
          AND n.last_heartbeat_at>$3 AND n.routing_observed_at>$3
          AND n.routing_state='ready' AND n.routing_accepting=TRUE AND n.routing_health IN ('healthy','degraded')
          AND (n.routing_capacity_max=0 OR n.routing_players_online + COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 h WHERE h.target_node_id=n.id AND ((h.status='active' AND h.expires_at>$4) OR (h.status='consumed' AND h.consumed_at>$4::timestamptz-interval '30 seconds'))),0) < n.routing_capacity_max)
        ORDER BY CASE n.routing_health WHEN 'healthy' THEN 0 ELSE 1 END,
                 CASE WHEN n.routing_capacity_max>0 THEN (n.routing_players_online + COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 h WHERE h.target_node_id=n.id AND ((h.status='active' AND h.expires_at>$4) OR (h.status='consumed' AND h.consumed_at>$4::timestamptz-interval '30 seconds'))),0))::double precision/n.routing_capacity_max ELSE 0 END,
                 n.name,n.id
        LIMIT 1024`, projectID, profileID, freshAfter, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ServerBridgeRouteTarget, 0)
	for rows.Next() {
		var item model.ServerBridgeRouteTarget
		var reserved int
		if err := rows.Scan(&item.NodeID, &item.BackendName, &item.Kind, &item.ProjectID, &item.ProfileID, &item.RuntimeID, &item.RuntimeEpoch, &item.Health, &item.State, &item.PlayersOnline, &item.CapacityMax, &item.RoutingRevision, &item.RoutingDigest, &item.ObservedAt, &item.LastHeartbeatAt, &reserved); err != nil {
			return nil, err
		}
		if item.CapacityMax > 0 {
			item.AvailableSlots = item.CapacityMax - item.PlayersOnline - reserved
			if item.AvailableSlots < 0 {
				item.AvailableSlots = 0
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// EnsureServerBridgeNodeRoutable is the final admission guard used by direct
// validate-join and handoff consumers. A 0.19.6 backend cannot accept a player
// merely because a launcher/session proof is valid; the exact runtime must also
// still advertise a fresh, accepting and non-full route state.
func (r *SQLRepository) EnsureServerBridgeNodeRoutable(ctx context.Context, serverID string, runtimeEpoch int64, runtimeID string, now time.Time) error {
	if err := r.check(); err != nil {
		return err
	}
	serverID = strings.TrimSpace(serverID)
	runtimeID = strings.ToLower(strings.TrimSpace(runtimeID))
	if serverID == "" || runtimeEpoch < 1 || len(runtimeID) != 64 {
		return fmt.Errorf("%w: runtime routing binding missing", ErrConflict)
	}
	freshAfter := now.UTC().Add(-serverBridgeRoutingFreshness0196)
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_bridge_nodes_v2 n WHERE n.id=$1 AND n.status='active' AND n.runtime_epoch=$2 AND n.runtime_id=$3 AND n.last_heartbeat_at>$4 AND n.routing_observed_at>$4 AND n.routing_state='ready' AND n.routing_accepting=TRUE AND n.routing_health IN ('healthy','degraded') AND (n.routing_capacity_max=0 OR n.routing_players_online + COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 h WHERE h.target_node_id=n.id AND ((h.status='active' AND h.expires_at>$5) OR (h.status='consumed' AND h.consumed_at>$5::timestamptz-interval '30 seconds'))),0) < n.routing_capacity_max))`, serverID, runtimeEpoch, runtimeID, freshAfter, now.UTC()).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: node is stale, unhealthy, draining, in maintenance, or at capacity", ErrConflict)
	}
	return nil
}
