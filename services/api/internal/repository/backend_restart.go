package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// BackendRestartJournal provides durable at-most-once scheduling across API restarts.
// An accepted restart is never implicitly rescheduled on a retry (including after a crash).
type BackendRestartJournal interface {
	ClaimBackendRestart0289(context.Context, string, string, string) (BackendRestartRecord0289, bool, error)
}

type BackendRestartRecord0289 struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instanceId"`
	Actor      string    `json:"actor"`
	AcceptedAt time.Time `json:"acceptedAt"`
	State      string    `json:"state"`
}

func BackendRestartKey0289(actor, key string) (string, error) {
	if actor == "" || len(key) < 16 || len(key) > 128 {
		return "", errors.New("invalid restart idempotency key")
	}
	for _, c := range key {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return "", errors.New("invalid restart idempotency key")
		}
	}
	sum := sha256.Sum256([]byte(actor + "\x00" + key))
	return hex.EncodeToString(sum[:]), nil
}

func (r *SQLRepository) ClaimBackendRestart0289(ctx context.Context, actor, key, instance string) (BackendRestartRecord0289, bool, error) {
	id, err := BackendRestartKey0289(actor, key)
	if err != nil {
		return BackendRestartRecord0289{}, false, err
	}
	if strings.TrimSpace(instance) == "" {
		return BackendRestartRecord0289{}, false, errors.New("instance identity is required")
	}
	if err := r.check(); err != nil {
		return BackendRestartRecord0289{}, false, err
	}
	// Conflict handling is serialized by PostgreSQL's unique index. The first claim
	// wins regardless of which replica receives subsequent requests.
	row := r.db.QueryRowContext(ctx, `INSERT INTO backend_restart_requests_0289 (id, actor, instance_id, state)
 VALUES ($1,$2,$3,'accepted') ON CONFLICT DO NOTHING RETURNING id,actor,instance_id,state,accepted_at`, id, actor, instance)
	var rec BackendRestartRecord0289
	err = row.Scan(&rec.ID, &rec.Actor, &rec.InstanceID, &rec.State, &rec.AcceptedAt)
	if err == nil {
		return rec, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rec, false, fmt.Errorf("claim backend restart: %w", err)
	}
	err = r.db.QueryRowContext(ctx, `SELECT id,actor,instance_id,state,accepted_at FROM backend_restart_requests_0289 WHERE id=$1`, id).Scan(&rec.ID, &rec.Actor, &rec.InstanceID, &rec.State, &rec.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BackendRestartRecord0289{}, false, ErrConflict
	}
	return rec, false, err
}
