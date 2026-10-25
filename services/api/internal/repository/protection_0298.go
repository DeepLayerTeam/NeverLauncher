package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ProtectionBan is independent from a user's disabled status. An unban must
// never re-enable an account that was independently disabled.
type ProtectionBan struct {
	UserID    string     `json:"userId"`
	Reason    string     `json:"reason"`
	Actor     string     `json:"actor"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	RevokedBy string     `json:"revokedBy,omitempty"`
}
type ProtectionBanStore interface {
	ActiveProtectionBan(context.Context, string, time.Time) (ProtectionBan, bool, error)
	SetProtectionBan(context.Context, ProtectionBan) error
	RevokeProtectionBan(context.Context, string, string) (bool, error)
	ListProtectionBans(context.Context) ([]ProtectionBan, error)
}

func (r *SQLRepository) ActiveProtectionBan(ctx context.Context, userID string, now time.Time) (ProtectionBan, bool, error) {
	if err := r.check(); err != nil {
		return ProtectionBan{}, false, err
	}
	var b ProtectionBan
	err := r.db.QueryRowContext(ctx, `SELECT user_id,reason,actor,created_at,expires_at FROM protection_bans WHERE user_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2)`, userID, now).Scan(&b.UserID, &b.Reason, &b.Actor, &b.CreatedAt, &b.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProtectionBan{}, false, nil
	}
	return b, err == nil, err
}
func (r *SQLRepository) SetProtectionBan(ctx context.Context, b ProtectionBan) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	// Serialize creation of fresh sessions and account-wide bans on one user row.
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, b.UserID).Scan(&id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO protection_bans(user_id,reason,actor,created_at,expires_at) VALUES($1,$2,$3,now(),$4) ON CONFLICT(user_id) DO UPDATE SET reason=EXCLUDED.reason,actor=EXCLUDED.actor,created_at=now(),expires_at=EXCLUDED.expires_at,revoked_at=NULL,revoked_by=NULL`, b.UserID, b.Reason, b.Actor, b.ExpiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLRepository) RevokeProtectionBan(ctx context.Context, userID, actor string) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE protection_bans SET revoked_at=now(),revoked_by=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, actor)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
func (r *SQLRepository) ListProtectionBans(ctx context.Context) ([]ProtectionBan, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT user_id,reason,actor,created_at,expires_at,revoked_at,coalesce(revoked_by,'') FROM protection_bans ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProtectionBan{}
	for rows.Next() {
		var b ProtectionBan
		if err := rows.Scan(&b.UserID, &b.Reason, &b.Actor, &b.CreatedAt, &b.ExpiresAt, &b.RevokedAt, &b.RevokedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (r *MemoryRepository) ActiveProtectionBan(_ context.Context, userID string, now time.Time) (ProtectionBan, bool, error) {
	r.protectionMu.RLock()
	defer r.protectionMu.RUnlock()
	b, ok := r.protectionBans[userID]
	if !ok || b.RevokedAt != nil || (b.ExpiresAt != nil && !b.ExpiresAt.After(now)) {
		return ProtectionBan{}, false, nil
	}
	return b, true, nil
}
func (r *MemoryRepository) SetProtectionBan(_ context.Context, b ProtectionBan) error {
	if strings.TrimSpace(b.UserID) == "" {
		return ErrNotFound
	}
	r.protectionMu.Lock()
	defer r.protectionMu.Unlock()
	if r.protectionBans == nil {
		r.protectionBans = make(map[string]ProtectionBan)
	}
	b.CreatedAt = time.Now().UTC()
	b.RevokedAt = nil
	b.RevokedBy = ""
	r.protectionBans[b.UserID] = b
	return nil
}
func (r *MemoryRepository) RevokeProtectionBan(_ context.Context, userID, actor string) (bool, error) {
	r.protectionMu.Lock()
	defer r.protectionMu.Unlock()
	b, ok := r.protectionBans[userID]
	if !ok || b.RevokedAt != nil {
		return false, nil
	}
	now := time.Now().UTC()
	b.RevokedAt = &now
	b.RevokedBy = actor
	r.protectionBans[userID] = b
	return true, nil
}
func (r *MemoryRepository) ListProtectionBans(_ context.Context) ([]ProtectionBan, error) {
	r.protectionMu.RLock()
	defer r.protectionMu.RUnlock()
	out := make([]ProtectionBan, 0, len(r.protectionBans))
	for _, b := range r.protectionBans {
		out = append(out, b)
	}
	return out, nil
}
