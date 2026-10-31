package sqlitecore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

var ErrBridgeUncertain = errors.New("bridge delivery outcome is indeterminate; manual reconciliation required")

// BridgeRuntimeHeartbeat is authenticated with the enrolled node's Ed25519 key.
// A different JVM runtime must advance epoch, not silently reuse it.
type BridgeRuntimeHeartbeat struct {
	Proof     NodeProof `json:"proof"`
	RuntimeID string    `json:"runtimeId"`
	Epoch     int64     `json:"epoch"`
	Sequence  int64     `json:"sequence"`
}

func bridgeRuntimePayload(b BridgeRuntimeHeartbeat) []byte {
	return []byte(fmt.Sprintf("Launcher/bridge-runtime/0.32.6\n%s\n%s\n%d\n%d\n", b.Proof.NodeID, b.RuntimeID, b.Epoch, b.Sequence))
}

func (r *Repository) HeartbeatBridgeRuntime(ctx context.Context, b BridgeRuntimeHeartbeat) error {
	if !isHex256(b.RuntimeID) || b.Epoch <= 0 || b.Sequence <= 0 {
		return ErrNodeProof
	}
	raw := bridgeRuntimePayload(b)
	digest := sha256.Sum256(raw)
	now := time.Now().UTC()
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := verifyProofTx(ctx, q, "runtime", b.Proof, hex.EncodeToString(digest[:]), now); e != nil {
			return e
		}
		nonce, e := base64.RawURLEncoding.DecodeString(b.Proof.Nonce)
		if e != nil {
			return ErrNodeProof
		}
		h := sha256.Sum256(nonce)
		result, e := q.ExecContext(ctx, `INSERT INTO bridge_runtime_nonces(node_id,epoch,nonce_hash,committed_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, b.Proof.NodeID, b.Proof.IdentityEpoch, hex.EncodeToString(h[:]), ns(now))
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrReplay
		}
		var runtime, state string
		var epoch, sequence int64
		e = q.QueryRowContext(ctx, `SELECT runtime_id,epoch,heartbeat_seq,status FROM bridge_runtime WHERE node_id=?`, b.Proof.NodeID).Scan(&runtime, &epoch, &sequence, &state)
		if e != nil && !errors.Is(e, ErrNotFound) && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && (b.Epoch < epoch || (b.Epoch == epoch && (state != "active" || b.RuntimeID != runtime || b.Sequence <= sequence))) {
			return ErrNodeProof
		}
		if e == nil && b.Epoch > epoch {
			// If the node restarted while commands were in flight, delivery cannot be assumed absent.
			if _, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status='indeterminate',completed_at=?,updated_at=?,failure='runtime superseded without acknowledgement' WHERE node_id=? AND status='leased'`, ns(now), ns(now), b.Proof.NodeID); e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status='expired',completed_at=?,updated_at=?,failure='runtime superseded before delivery' WHERE node_id=? AND status='pending'`, ns(now), ns(now), b.Proof.NodeID); e != nil {
				return e
			}
		}
		if e == nil && b.Epoch == epoch && b.RuntimeID == runtime {
			_, e = q.ExecContext(ctx, `UPDATE bridge_runtime SET last_heartbeat=?,heartbeat_seq=?,status='active' WHERE node_id=?`, ns(now), b.Sequence, b.Proof.NodeID)
		} else {
			_, e = q.ExecContext(ctx, `INSERT INTO bridge_runtime(node_id,runtime_id,epoch,status,last_heartbeat,heartbeat_seq,delivery_seq) VALUES(?,?,?,'active',?,?,0)
   ON CONFLICT(node_id) DO UPDATE SET runtime_id=excluded.runtime_id,epoch=excluded.epoch,status='active',last_heartbeat=excluded.last_heartbeat,heartbeat_seq=excluded.heartbeat_seq`, b.Proof.NodeID, b.RuntimeID, b.Epoch, ns(now), b.Sequence)
		}
		return e
	})
}

// Bridge commands are limited to typed plugin operations; NEVER execute shell or arbitrary argv.
var bridgeCommandTypes = map[string]bool{"broadcast": true, "save": true, "kick": true, "whitelist": true, "shutdown": true, "maintenance": true}

const bridgeCommandCols = `id,node_id,runtime_id,runtime_epoch,command_type,payload,payload_digest,request_digest,actor,idempotency_key,status,attempt,delivery_seq,lease_owner,lease_token,lease_until,created_at,updated_at,expires_at,completed_at,result,failure`

func scanBridgeCommand(row interface{ Scan(...any) error }) (c model.ServerBridgeControlCommand, e error) {
	var payload, result string
	var created, updated, expires, lease, completed int64
	e = row.Scan(&c.ID, &c.ServerID, &c.RuntimeID, &c.RuntimeEpoch, &c.Type, &payload, &c.PayloadSHA256, &c.RequestDigest, &c.RequestedBy, &c.IdempotencyKey, &c.Status, &c.Attempt, &c.DeliverySequence, &c.LeaseOwner, &c.LeaseToken, &lease, &created, &updated, &expires, &completed, &result, &c.Error)
	if e != nil {
		return c, notFound(e)
	}
	if e = json.Unmarshal([]byte(payload), &c.Payload); e != nil {
		return c, e
	}
	if e = json.Unmarshal([]byte(result), &c.Result); e != nil {
		return c, e
	}
	c.LeaseUntil = ts(lease)
	c.CreatedAt = ts(created)
	c.UpdatedAt = ts(updated)
	c.ExpiresAt = ts(expires)
	c.CompletedAt = ts(completed)
	return c, nil
}
func readBridgeCommand(ctx context.Context, q sqlitedurable.Executor, id string) (model.ServerBridgeControlCommand, error) {
	return scanBridgeCommand(q.QueryRowContext(ctx, "SELECT "+bridgeCommandCols+" FROM bridge_commands WHERE id=?", id))
}
func (r *Repository) GetBridgeCommand(ctx context.Context, id string) (c model.ServerBridgeControlCommand, e error) {
	e = r.store.Read(ctx, func(q sqlitedurable.Executor) error { c, e = readBridgeCommand(ctx, q, id); return e })
	return
}

func authorizedBridgeOperator(ctx context.Context, q sqlitedurable.Executor, node, actor string) error {
	var global, status, project string
	e := q.QueryRowContext(ctx, `SELECT u.role_id,u.status,n.project_id FROM users u JOIN bridge_nodes n ON n.id=? WHERE u.id=?`, node, actor).Scan(&global, &status, &project)
	if e != nil || status != "active" {
		return ErrAuthentication
	}
	if global == "owner" || global == "admin" {
		return nil
	}
	var role string
	e = q.QueryRowContext(ctx, `SELECT role_id FROM project_user_roles WHERE user_id=? AND project_id=?`, actor, project).Scan(&role)
	if e != nil || (role != "owner" && role != "admin") {
		return ErrAuthentication
	}
	return nil
}
func bridgePayload(payload map[string]string) (string, string, error) {
	if payload == nil {
		payload = map[string]string{}
	}
	if len(payload) > 32 {
		return "", "", errors.New("too many command parameters")
	}
	for k, v := range payload {
		if k == "" || len(k) > 80 || len(v) > 2048 || strings.ContainsAny(k, "\x00\r\n") || strings.ContainsRune(v, '\x00') {
			return "", "", errors.New("invalid command parameter")
		}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return "", "", e
	}
	if len(raw) > 8192 {
		return "", "", errors.New("command payload too large")
	}
	sum := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

// CreateBridgeCommand verifies the scoped operator and current signed runtime,
// commits an immutable idempotency tombstone and audit in one IMMEDIATE transaction.
func (r *Repository) CreateBridgeCommand(ctx context.Context, c model.ServerBridgeControlCommand) (out model.ServerBridgeControlCommand, created bool, err error) {
	if c.ID == "" {
		c.ID, err = newID("bc_")
		if err != nil {
			return
		}
	}
	if !durableFieldsNonempty(c.ID, c.ServerID, c.RequestedBy, c.IdempotencyKey) || len(c.IdempotencyKey) < 8 || !bridgeCommandTypes[c.Type] || !isHex256(c.RuntimeID) || c.RuntimeEpoch <= 0 || c.ExpiresAt.Before(time.Now()) || time.Until(c.ExpiresAt) > time.Hour {
		err = errors.New("invalid bridge command identity/type/expiry")
		return
	}
	payload, digest, e := bridgePayload(c.Payload)
	if e != nil {
		err = e
		return
	}
	requestBytes := []byte(c.RuntimeID + "\n" + fmt.Sprint(c.RuntimeEpoch) + "\n" + c.Type + "\n" + payload + "\n" + fmt.Sprint(ns(c.ExpiresAt)))
	h := sha256.Sum256(requestBytes)
	reqDigest := hex.EncodeToString(h[:])
	now := nowNS()
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedBridgeOperator(ctx, q, c.ServerID, c.RequestedBy); e != nil {
			return e
		}
		var runtime, status, nodeStatus string
		var epoch, last int64
		e := q.QueryRowContext(ctx, `SELECT r.runtime_id,r.epoch,r.status,r.last_heartbeat,n.status FROM bridge_runtime r JOIN bridge_nodes n ON n.id=r.node_id WHERE r.node_id=?`, c.ServerID).Scan(&runtime, &epoch, &status, &last, &nodeStatus)
		if e != nil {
			return notFound(e)
		}
		if runtime != c.RuntimeID || epoch != c.RuntimeEpoch || status != "active" || nodeStatus != "active" || last < now-int64(2*time.Minute) {
			return ErrNodeProof
		}
		existing, e := scanBridgeCommand(q.QueryRowContext(ctx, "SELECT "+bridgeCommandCols+" FROM bridge_commands WHERE node_id=? AND actor=? AND idempotency_key=?", c.ServerID, c.RequestedBy, c.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != reqDigest {
				return ErrDurableIdempotency
			}
			out = existing
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO bridge_commands(id,node_id,runtime_id,runtime_epoch,command_type,payload,payload_digest,request_digest,actor,idempotency_key,status,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?,?)`, c.ID, c.ServerID, c.RuntimeID, c.RuntimeEpoch, c.Type, payload, digest, reqDigest, c.RequestedBy, c.IdempotencyKey, now, now, ns(c.ExpiresAt))
		if e != nil {
			return conflict(e)
		}
		if e = recordAudit(ctx, q, audit(c.RequestedBy, "bridge:command-queue", c.ServerID+":"+c.ID)); e != nil {
			return e
		}
		created = true
		out, e = readBridgeCommand(ctx, q, c.ID)
		return e
	})
	return
}

// LeaseBridgeCommand is single-delivery. A lost ACK is indeterminate, NEVER automatically redelivered.
func (r *Repository) LeaseBridgeCommand(ctx context.Context, proof NodeProof, runtime string, epoch int64, worker string, after int64, ttl time.Duration) (out model.ServerBridgeControlCommand, err error) {
	node := proof.NodeID
	if !durableFieldsNonempty(node, worker) || !isHex256(runtime) || epoch < 1 || len(worker) < 8 || after < 0 || ttl < time.Second || ttl > time.Minute {
		return out, errors.New("invalid bridge dispatch parameters")
	}
	noCommand := false
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := verifyAndConsumeBridgeControlProof(ctx, q, "control-lease", proof, bridgeLeasePayload(runtime, epoch, worker, after, ttl)); e != nil {
			return e
		}
		now := nowNS()
		var actual, status, nodeStatus string
		var actualEpoch, last int64
		e := q.QueryRowContext(ctx, `SELECT r.runtime_id,r.epoch,r.status,r.last_heartbeat,n.status FROM bridge_runtime r JOIN bridge_nodes n ON n.id=r.node_id WHERE r.node_id=?`, node).Scan(&actual, &actualEpoch, &status, &last, &nodeStatus)
		if e != nil {
			return notFound(e)
		}
		if actual != runtime || actualEpoch != epoch || status != "active" || nodeStatus != "active" || last < now-int64(2*time.Minute) {
			return ErrNodeProof
		}
		if _, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status='expired',failure='expired before dispatch',updated_at=?,completed_at=? WHERE node_id=? AND status='pending' AND expires_at<=?`, now, now, node, now); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status='indeterminate',failure='delivery ACK missing; manual reconciliation required',updated_at=?,completed_at=? WHERE node_id=? AND status='leased' AND lease_until<=?`, now, now, node, now); e != nil {
			return e
		}
		var id string
		e = q.QueryRowContext(ctx, `SELECT id FROM bridge_commands WHERE node_id=? AND runtime_id=? AND runtime_epoch=? AND status='leased' AND lease_owner=? AND lease_until>? AND delivery_seq>? ORDER BY delivery_seq LIMIT 1`, node, runtime, epoch, worker, now, after).Scan(&id)
		if e == nil {
			out, e = readBridgeCommand(ctx, q, id)
			return e
		} else if !isNoRows(e) {
			return e
		}
		e = q.QueryRowContext(ctx, `SELECT id FROM bridge_commands WHERE node_id=? AND runtime_id=? AND runtime_epoch=? AND status='pending' AND expires_at>? ORDER BY created_at,id LIMIT 1`, node, runtime, epoch, now).Scan(&id)
		if isNoRows(e) {
			// Commit expiry reconciliation even if no pending command remains.
			noCommand = true
			return nil
		}
		if e != nil {
			return e
		}
		token, e := newLeaseToken()
		if e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `UPDATE bridge_runtime SET delivery_seq=delivery_seq+1 WHERE node_id=?`, node); e != nil {
			return e
		}
		var seq int64
		if e = q.QueryRowContext(ctx, `SELECT delivery_seq FROM bridge_runtime WHERE node_id=?`, node).Scan(&seq); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status='leased',attempt=1,delivery_seq=?,lease_owner=?,lease_token=?,lease_until=?,updated_at=? WHERE id=? AND status='pending'`, seq, worker, token, now+int64(ttl), now, id)
		if e != nil {
			return e
		}
		if e = recordAudit(ctx, q, audit(node, "bridge:command-delivered", id)); e != nil {
			return e
		}
		out, e = readBridgeCommand(ctx, q, id)
		return e
	})
	if err == nil && noCommand {
		err = ErrNotFound
	}
	return
}

func (r *Repository) CompleteBridgeCommand(ctx context.Context, proof NodeProof, id, runtime, worker, token string, epoch, seq int64, status string, result map[string]string, failure string) (out model.ServerBridgeControlCommand, err error) {
	node := proof.NodeID
	if !map[string]bool{"succeeded": true, "failed": true, "unsupported": true}[status] || !isHex256(token) || !isHex256(runtime) || epoch < 1 || seq < 1 || worker == "" {
		return out, errors.New("invalid bridge acknowledgement")
	}
	encoded, _, e := bridgePayload(result)
	if e != nil {
		return out, e
	}
	if len(failure) > 1024 {
		failure = failure[:1024]
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := verifyAndConsumeBridgeControlProof(ctx, q, "control-ack", proof, bridgeAckPayload(id, runtime, worker, token, epoch, seq, status, encoded, failure)); e != nil {
			return e
		}
		c, e := readBridgeCommand(ctx, q, id)
		if e != nil {
			return e
		}
		if c.ServerID != node || c.RuntimeID != runtime || c.RuntimeEpoch != epoch || c.LeaseOwner != worker || c.LeaseToken != token || c.DeliverySequence != seq {
			return ErrBridgeUncertain
		}
		if c.Status == status {
			prev, _ := json.Marshal(c.Result)
			if string(prev) == encoded && c.Error == failure {
				out = c
				return nil
			}
			return ErrConflict
		}
		if c.Status != "leased" || !time.Now().Before(c.LeaseUntil) {
			return ErrBridgeUncertain
		}
		var cur string
		var curEpoch int64
		var active string
		if e = q.QueryRowContext(ctx, `SELECT r.runtime_id,r.epoch,n.status FROM bridge_runtime r JOIN bridge_nodes n ON n.id=r.node_id WHERE r.node_id=?`, node).Scan(&cur, &curEpoch, &active); e != nil {
			return e
		}
		if cur != runtime || curEpoch != epoch || active != "active" {
			return ErrBridgeUncertain
		}
		now := nowNS()
		_, e = q.ExecContext(ctx, `UPDATE bridge_commands SET status=?,result=?,failure=?,updated_at=?,completed_at=? WHERE id=? AND status='leased'`, status, encoded, failure, now, now, id)
		if e != nil {
			return e
		}
		if e = recordAudit(ctx, q, audit(node, "bridge:command-complete", id)); e != nil {
			return e
		}
		out, e = readBridgeCommand(ctx, q, id)
		return e
	})
	return
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// Invalidate pending and leased commands atomically on key rotation or disable.
// An already delivered command cannot be retried because its outcome is unknown.
func invalidateBridgeRuntimeTx(ctx context.Context, q sqlitedurable.Executor, node, reason string, now int64) error {
	if _, e := q.ExecContext(ctx, `UPDATE bridge_commands SET status='indeterminate',failure=?,updated_at=?,completed_at=? WHERE node_id=? AND status='leased'`, reason, now, now, node); e != nil {
		return e
	}
	if _, e := q.ExecContext(ctx, `UPDATE bridge_commands SET status='expired',failure=?,updated_at=?,completed_at=? WHERE node_id=? AND status='pending'`, reason, now, now, node); e != nil {
		return e
	}
	_, e := q.ExecContext(ctx, `UPDATE bridge_runtime SET status='disabled' WHERE node_id=?`, node)
	return e
}

// The signed payload binds every dispatch/ACK parameter to the enrolled node key.
func bridgeLeasePayload(runtime string, epoch int64, worker string, after int64, ttl time.Duration) []byte {
	return []byte(fmt.Sprintf("Launcher/bridge-lease/0.32.6\n%s\n%d\n%s\n%d\n%d\n", runtime, epoch, worker, after, int64(ttl)))
}
func bridgeAckPayload(id, runtime, worker, token string, epoch, seq int64, status, encoded, failure string) []byte {
	return []byte(fmt.Sprintf("Launcher/bridge-ack/0.32.6\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%s\n", id, runtime, worker, token, epoch, seq, status, encoded, failure))
}
func verifyAndConsumeBridgeControlProof(ctx context.Context, q sqlitedurable.Executor, action string, proof NodeProof, payload []byte) error {
	now := time.Now().UTC()
	h := sha256.Sum256(payload)
	if e := verifyProofTx(ctx, q, action, proof, hex.EncodeToString(h[:]), now); e != nil {
		return e
	}
	raw, e := base64.RawURLEncoding.DecodeString(proof.Nonce)
	if e != nil {
		return ErrNodeProof
	}
	nonceHash := sha256.Sum256(raw)
	res, e := q.ExecContext(ctx, `INSERT INTO bridge_runtime_nonces(node_id,epoch,nonce_hash,committed_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, proof.NodeID, proof.IdentityEpoch, hex.EncodeToString(nonceHash[:]), ns(now))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrReplay
	}
	return nil
}
