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

// ListServerBridgeNetworkStates reads observed, runtime-bound routing and operator
// admission policy from the same PostgreSQL source used by handoff execution.
// It intentionally never infers a healthy route from heartbeat alone.
func (r *SQLRepository) ListServerBridgeNetworkStates(ctx context.Context, projectID string, now time.Time) ([]model.ServerBridgeNetworkState, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT n.id,n.runtime_id,n.runtime_epoch,n.routing_state,n.routing_health,
        n.routing_accepting,n.routing_players_online,n.routing_capacity_max,n.operator_capacity_max,
        n.operator_capacity_revision,n.routing_revision,n.routing_observed_at,n.last_heartbeat_at,
        n.operator_capacity_updated_at,n.operator_capacity_updated_by,n.status,
        COALESCE((SELECT count(*) FROM server_bridge_handoffs_v2 h WHERE h.target_node_id=n.id
            AND ((h.status='active' AND h.expires_at>$2) OR
                 (h.status='consumed' AND h.consumed_at>$2::timestamptz-interval '30 seconds'))),0)
        FROM server_bridge_nodes_v2 n WHERE ($1='' OR n.project_id=$1) ORDER BY n.name,n.id LIMIT 5000`,
		projectID, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ServerBridgeNetworkState, 0)
	for rows.Next() {
		var n model.ServerBridgeNetworkState
		var limit sql.NullInt64
		var observed, heartbeat, updated sql.NullTime
		var status string
		if err := rows.Scan(&n.NodeID, &n.RuntimeID, &n.RuntimeEpoch, &n.State, &n.Health,
			&n.AcceptingConnections, &n.PlayersOnline, &n.CapacityMax, &limit,
			&n.OperatorCapacityRevision, &n.RoutingRevision, &observed, &heartbeat,
			&updated, &n.OperatorUpdatedBy, &status, &n.ReservedSlots); err != nil {
			return nil, err
		}
		if limit.Valid {
			v := int(limit.Int64)
			n.OperatorCapacityMax = &v
		}
		if observed.Valid {
			t := observed.Time.UTC()
			n.ObservedAt = &t
		}
		if heartbeat.Valid {
			t := heartbeat.Time.UTC()
			n.LastHeartbeatAt = &t
		}
		if updated.Valid {
			t := updated.Time.UTC()
			n.OperatorUpdatedAt = &t
		}
		n.Source = "postgresql:signed-runtime-routing+operator-admission"
		n.EffectiveCapacityMax = effectiveBridgeCapacity0288(n.CapacityMax, n.OperatorCapacityMax)
		switch {
		case status != "active" || n.RuntimeEpoch < 1 || len(n.RuntimeID) != 64 || n.RoutingRevision < 1 || n.ObservedAt == nil || n.LastHeartbeatAt == nil || !n.ObservedAt.After(now.Add(-serverBridgeRoutingFreshness0196)) || !n.LastHeartbeatAt.After(now.Add(-serverBridgeRoutingFreshness0196)):
			n.Reason = "stale-or-unverified-runtime"
		case n.State != "ready":
			n.Reason = n.State
		case n.Health != "healthy" && n.Health != "degraded":
			n.Reason = "unhealthy"
		case !n.AcceptingConnections:
			n.Reason = "node-denies-admission"
		case n.OperatorCapacityMax != nil && *n.OperatorCapacityMax == 0:
			n.Reason = "operator-capacity-zero"
		case n.CapacityMax > 0 && n.PlayersOnline+n.ReservedSlots >= n.CapacityMax:
			n.Reason = "node-full"
		case n.OperatorCapacityMax != nil && n.PlayersOnline+n.ReservedSlots >= *n.OperatorCapacityMax:
			n.Reason = "operator-capacity-full"
		default:
			n.Routable = true
			n.Reason = "ready"
		}
		if n.CapacityMax == 0 && n.OperatorCapacityMax == nil {
			n.AvailableSlots = -1
		} else {
			n.AvailableSlots = n.EffectiveCapacityMax - n.PlayersOnline - n.ReservedSlots
			if n.AvailableSlots < 0 {
				n.AvailableSlots = 0
			}
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// SetServerBridgeNetworkCapacity applies an operator ceiling atomically with an
// optimistic revision and exact runtime precondition. The target row lock also
// serializes policy changes against handoff minting (which takes FOR UPDATE).
func (r *SQLRepository) SetServerBridgeNetworkCapacity(ctx context.Context, serverID, projectID, runtimeID string, runtimeEpoch, expectedRevision int64, limit *int, actor string, now time.Time) (int64, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	if serverID == "" || projectID == "" || len(runtimeID) != 64 || runtimeEpoch < 1 || expectedRevision < 0 || actor == "" || (limit != nil && (*limit < 0 || *limit > 1000000)) {
		return 0, fmt.Errorf("%w: invalid network capacity request", ErrConflict)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var revision int64
	var kind, status, actualRuntimeID string
	var actualEpoch int64
	err = tx.QueryRowContext(ctx, `SELECT kind,status,runtime_id,runtime_epoch,operator_capacity_revision FROM server_bridge_nodes_v2 WHERE id=$1 AND project_id=$2 FOR UPDATE`, serverID, projectID).
		Scan(&kind, &status, &actualRuntimeID, &actualEpoch, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if !isBackendBridgeKind0148(kind) || status != "active" || !strings.EqualFold(actualRuntimeID, runtimeID) || actualEpoch != runtimeEpoch || revision != expectedRevision {
		return 0, fmt.Errorf("%w: network capacity runtime or revision changed", ErrConflict)
	}
	var value any
	if limit != nil {
		value = *limit
	}
	var newRevision int64
	if err = tx.QueryRowContext(ctx, `UPDATE server_bridge_nodes_v2 SET operator_capacity_max=$2,operator_capacity_revision=operator_capacity_revision+1,operator_capacity_updated_at=$3,operator_capacity_updated_by=$4 WHERE id=$1 RETURNING operator_capacity_revision`, serverID, value, now.UTC(), actor).Scan(&newRevision); err != nil {
		return 0, err
	}
	// Existing unredeemed tickets may refer to an earlier, less restrictive
	// route. Invalidating them is safer than allowing a capacity race.
	if _, err = tx.ExecContext(ctx, `UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=$2 WHERE target_node_id=$1 AND status='active'`, serverID, now.UTC()); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return newRevision, nil
}
