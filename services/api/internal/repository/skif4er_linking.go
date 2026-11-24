package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Skif4erUnlinkRepository102 is implemented by all supported HTTP repositories.
// The owner must retain a local password identity. Never delete another provider.
type Skif4erUnlinkRepository102 interface {
	UnlinkSkif4er102(ctx context.Context, userID, identityID string) error
}

func (r *MemoryRepository) UnlinkSkif4er102(_ context.Context, userID, identityID string) error {
	r.identityMu.Lock()
	defer r.identityMu.Unlock()
	r.userMu.RLock()
	defer r.userMu.RUnlock()
	var user model.User
	for _, candidate := range r.users {
		if candidate.ID == userID {
			user = candidate
			break
		}
	}
	if user.ID == "" {
		return ErrNotFound
	}
	if user.Status != "active" || strings.TrimSpace(user.PasswordHash) == "" {
		return ErrConflict
	}
	local := false
	index := -1
	for i, item := range r.identities {
		if item.UserID != userID {
			continue
		}
		if item.Provider == "local" && item.Subject == userID {
			local = true
		}
		if item.ID == identityID && item.Provider == "skif4er-id" {
			index = i
		}
	}
	if index < 0 {
		return ErrNotFound
	}
	if !local {
		return ErrConflict
	}
	for i := len(r.providerCredentials) - 1; i >= 0; i-- {
		if r.providerCredentials[i].IdentityID == identityID {
			r.providerCredentials = append(r.providerCredentials[:i], r.providerCredentials[i+1:]...)
		}
	}
	r.identities = append(r.identities[:index], r.identities[index+1:]...)
	return nil
}

func (r *SQLiteHTTPRepository0372) UnlinkSkif4er102(ctx context.Context, userID, identityID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if err := r.mem.UnlinkSkif4er102(ctx, userID, identityID); err != nil {
		return err
	}
	if err := r.persist(ctx); err != nil {
		r.failed = err
		return err
	}
	return nil
}

func (r *SQLRepository) UnlinkSkif4er102(ctx context.Context, userID, identityID string) error {
	if err := r.check(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var password, status string
	err = tx.QueryRowContext(ctx, `SELECT password_hash,status FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&password, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" || strings.TrimSpace(password) == "" {
		return ErrConflict
	}
	var local bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_identities WHERE user_id=$1 AND provider='local' AND subject=$1)`, userID).Scan(&local); err != nil {
		return err
	}
	if !local {
		return ErrConflict
	}
	// The FK removes encrypted provider credentials in the same transaction.
	res, err := tx.ExecContext(ctx, `DELETE FROM auth_identities WHERE id=$1 AND user_id=$2 AND provider='skif4er-id'`, identityID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return tx.Commit()
}
