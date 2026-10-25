package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type BackendNotice0289 struct {
	ID              string    `json:"id"`
	RecipientUserID string    `json:"recipientUserId"`
	Body            string    `json:"body"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type BackendNoticeStore0289 interface {
	EnqueueBackendNotice0289(context.Context, string, string, string, string) (BackendNotice0289, bool, error)
	ListBackendNotices0289(context.Context, string) ([]BackendNotice0289, error)
	AckBackendNotice0289(context.Context, string, string) (bool, error)
}

func ValidateBackendNotice0289(recipient, body string) error {
	if strings.TrimSpace(recipient) == "" || len(recipient) > 128 {
		return errors.New("invalid recipient user ID")
	}
	if len(strings.TrimSpace(body)) < 1 || len([]rune(body)) > 512 {
		return errors.New("notice must be 1-512 characters")
	}
	for _, c := range body {
		if c < 32 && c != '\n' && c != '\t' {
			return errors.New("notice contains control characters")
		}
	}
	return nil
}
func (r *SQLRepository) EnqueueBackendNotice0289(ctx context.Context, actor, key, recipient, body string) (BackendNotice0289, bool, error) {
	var out BackendNotice0289
	id, err := BackendRestartKey0289(actor, key)
	if err != nil {
		return out, false, err
	}
	body = strings.TrimSpace(body)
	if err = ValidateBackendNotice0289(recipient, body); err != nil {
		return out, false, err
	}
	if err = r.check(); err != nil {
		return out, false, err
	}
	err = r.db.QueryRowContext(ctx, `INSERT INTO backend_notices_0289(id,actor,recipient_user_id,body)
  VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING
  RETURNING id,recipient_user_id,body,created_at,expires_at`, id, actor, recipient, body).
		Scan(&out.ID, &out.RecipientUserID, &out.Body, &out.CreatedAt, &out.ExpiresAt)
	if err == nil {
		return out, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, false, err
	}
	err = r.db.QueryRowContext(ctx, `SELECT id,recipient_user_id,body,created_at,expires_at FROM backend_notices_0289 WHERE id=$1`, id).
		Scan(&out.ID, &out.RecipientUserID, &out.Body, &out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		return out, false, err
	}
	// Replaying a key with a different payload cannot silently return success.
	if recipient != out.RecipientUserID || body != out.Body {
		return BackendNotice0289{}, false, fmt.Errorf("notification idempotency key already used with different content: %w", ErrConflict)
	}
	return out, false, nil
}
func (r *SQLRepository) ListBackendNotices0289(ctx context.Context, userID string) ([]BackendNotice0289, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,recipient_user_id,body,created_at,expires_at FROM backend_notices_0289
 WHERE recipient_user_id=$1 AND acknowledged_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BackendNotice0289, 0)
	for rows.Next() {
		var rec BackendNotice0289
		if err = rows.Scan(&rec.ID, &rec.RecipientUserID, &rec.Body, &rec.CreatedAt, &rec.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
func (r *SQLRepository) AckBackendNotice0289(ctx context.Context, userID, id string) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE backend_notices_0289 SET acknowledged_at=now()
 WHERE id=$1 AND recipient_user_id=$2 AND acknowledged_at IS NULL AND expires_at>now()`, id, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
