package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// HostOperation0413 is a durable Backend-to-RemoteControl-to-Supervisor record.
// A newly inserted record is indeterminate BEFORE the network side-effect:
// callers may inspect or reconcile but cannot automatically redispatch it.
type HostOperation0413 struct {
	ID                   string          `json:"id"`
	ServerID             string          `json:"serverId"`
	Action               string          `json:"action"`
	RequestedBy          string          `json:"requestedBy"`
	IdempotencyKey       string          `json:"idempotencyKey"`
	RequestDigest        string          `json:"-"`
	RemoteNodeID         string          `json:"remoteNodeId"`
	BaselineRuntimeID    string          `json:"baselineRuntimeId,omitempty"`
	BaselineRuntimeEpoch int64           `json:"baselineRuntimeEpoch"`
	State                string          `json:"status"`
	HostBefore           json.RawMessage `json:"hostBefore,omitempty"`
	HostAfter            json.RawMessage `json:"hostAfter,omitempty"`
	RemoteReceipt        json.RawMessage `json:"remoteReceipt,omitempty"`
	Error                string          `json:"error,omitempty"`
	CreatedAt            time.Time       `json:"createdAt"`
	UpdatedAt            time.Time       `json:"updatedAt"`
}

const hostOperationSelect0413 = `SELECT id,server_id,action,requested_by,idempotency_key,request_digest,remote_node_id,baseline_runtime_id,baseline_runtime_epoch,status,host_before,host_after,remote_receipt,error,created_at,updated_at FROM server_bridge_host_operations_0413`

func scanHostOperation0413(row interface{ Scan(...any) error }) (HostOperation0413, error) {
	var op HostOperation0413
	var before, after, receipt []byte
	err := row.Scan(&op.ID, &op.ServerID, &op.Action, &op.RequestedBy, &op.IdempotencyKey, &op.RequestDigest, &op.RemoteNodeID, &op.BaselineRuntimeID, &op.BaselineRuntimeEpoch, &op.State, &before, &after, &receipt, &op.Error, &op.CreatedAt, &op.UpdatedAt)
	op.HostBefore = before
	op.HostAfter = after
	op.RemoteReceipt = receipt
	return op, err
}
func (r *SQLRepository) CreateHostOperation0413(ctx context.Context, op HostOperation0413) (HostOperation0413, bool, error) {
	if err := r.check(); err != nil {
		return HostOperation0413{}, false, err
	}
	if op.ID == "" || op.ServerID == "" || op.RequestDigest == "" || op.RemoteNodeID == "" || op.IdempotencyKey == "" {
		return HostOperation0413{}, false, errors.New("host operation missing required fields")
	}
	before := op.HostBefore
	if len(before) == 0 {
		before = []byte(`{}`)
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO server_bridge_host_operations_0413(id,server_id,action,requested_by,idempotency_key,request_digest,remote_node_id,baseline_runtime_id,baseline_runtime_epoch,status,host_before) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'indeterminate',$10::jsonb) ON CONFLICT (server_id,idempotency_key) DO NOTHING`, op.ID, op.ServerID, op.Action, op.RequestedBy, op.IdempotencyKey, op.RequestDigest, op.RemoteNodeID, op.BaselineRuntimeID, op.BaselineRuntimeEpoch, string(before))
	if err != nil {
		var sqlState interface{ SQLState() string }
		if errors.As(err, &sqlState) && sqlState.SQLState() == "23505" {
			return HostOperation0413{}, false, ErrConflict
		}
		return HostOperation0413{}, false, fmt.Errorf("persist host command intent: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return HostOperation0413{}, false, err
	}
	found, err := scanHostOperation0413(r.db.QueryRowContext(ctx, hostOperationSelect0413+` WHERE server_id=$1 AND idempotency_key=$2`, op.ServerID, op.IdempotencyKey))
	if err != nil {
		return HostOperation0413{}, false, err
	}
	if found.RequestDigest != op.RequestDigest || found.Action != op.Action || found.RequestedBy != op.RequestedBy || found.RemoteNodeID != op.RemoteNodeID {
		return HostOperation0413{}, false, ErrConflict
	}
	return found, count == 0, nil
}
func (r *SQLRepository) GetHostOperationByKey0413(ctx context.Context, serverID, key string) (HostOperation0413, error) {
	if err := r.check(); err != nil {
		return HostOperation0413{}, err
	}
	op, err := scanHostOperation0413(r.db.QueryRowContext(ctx, hostOperationSelect0413+` WHERE server_id=$1 AND idempotency_key=$2`, serverID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return HostOperation0413{}, ErrNotFound
	}
	return op, err
}
func (r *SQLRepository) GetHostOperation0413(ctx context.Context, serverID, operationID string) (HostOperation0413, error) {
	if err := r.check(); err != nil {
		return HostOperation0413{}, err
	}
	op, err := scanHostOperation0413(r.db.QueryRowContext(ctx, hostOperationSelect0413+` WHERE server_id=$1 AND id=$2`, serverID, operationID))
	if errors.Is(err, sql.ErrNoRows) {
		return HostOperation0413{}, ErrNotFound
	}
	return op, err
}
func (r *SQLRepository) FinishHostOperation0413(ctx context.Context, op HostOperation0413, allowedState string) (HostOperation0413, error) {
	if err := r.check(); err != nil {
		return HostOperation0413{}, err
	}
	// Immutable terminal receipt. A stale Backend replica cannot overwrite result.
	res, err := r.db.ExecContext(ctx, `UPDATE server_bridge_host_operations_0413 SET status=$3,host_after=$4::jsonb,remote_receipt=$5::jsonb,error=$6,updated_at=now() WHERE id=$1 AND server_id=$2 AND status=$7`, op.ID, op.ServerID, op.State, rawJSON0413(op.HostAfter), rawJSON0413(op.RemoteReceipt), op.Error, allowedState)
	if err != nil {
		return HostOperation0413{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return HostOperation0413{}, err
	}
	if n != 1 {
		return HostOperation0413{}, ErrConflict
	}
	return r.GetHostOperation0413(ctx, op.ServerID, op.ID)
}
func rawJSON0413(v json.RawMessage) string {
	if len(v) == 0 {
		return "{}"
	}
	return string(v)
}
