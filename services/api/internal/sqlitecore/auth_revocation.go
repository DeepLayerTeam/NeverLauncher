package sqlitecore

import (
	"context"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"strings"
)

// Every revocation is applied to sessions, token families, access tokens,
// refresh tokens and Minecraft sessions in one durable transaction.
func (a *Auth) revokeSessionTx(ctx context.Context, q sqlitedurable.Executor, id, reason string, now int64) error {
	var userID string
	if e := q.QueryRowContext(ctx, `SELECT user_id FROM auth_sessions WHERE id=?`, id).Scan(&userID); e != nil {
		return notFound(e)
	}
	if _, e := q.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked',revoked_at=?,revoked_reason=? WHERE id=? AND status='active'`, now, reason, id); e != nil {
		return e
	}
	if _, e := q.ExecContext(ctx, `UPDATE refresh_families SET status='revoked',revoked_at=? WHERE session_id=? AND status='active'`, now, id); e != nil {
		return e
	}
	if _, e := q.ExecContext(ctx, `UPDATE refresh_tokens SET status='revoked' WHERE family_id IN(SELECT id FROM refresh_families WHERE session_id=?) AND status='current'`, id); e != nil {
		return e
	}
	if _, e := q.ExecContext(ctx, `UPDATE access_tokens SET revoked_at=? WHERE session_id=? AND revoked_at=0`, now, id); e != nil {
		return e
	}
	if _, e := q.ExecContext(ctx, `UPDATE minecraft_sessions SET status='revoked',revoked_at=?,revoked_reason=? WHERE session_id=? AND status='active'`, now, reason, id); e != nil {
		return e
	}
	eid, e := newID("rev-")
	if e != nil {
		return e
	}
	if _, e = q.ExecContext(ctx, `INSERT INTO auth_revocation_events(id,user_id,session_id,reason,created_at) VALUES(?,?,?,?,?)`, eid, userID, id, reason, now); e != nil {
		return e
	}
	return nil
}

func (a *Auth) RevokeSession(ctx context.Context, userID, sessionID, reason string) error {
	if userID == "" || sessionID == "" || strings.TrimSpace(reason) == "" {
		return errors.New("revocation requires owner, session and reason")
	}
	return a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var owner string
		if e := q.QueryRowContext(ctx, `SELECT user_id FROM auth_sessions WHERE id=?`, sessionID).Scan(&owner); e != nil {
			return notFound(e)
		}
		if owner != userID {
			return ErrAuthentication
		}
		if e := a.revokeSessionTx(ctx, q, sessionID, reason, nowNS()); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(userID, "auth:session-revoke", sessionID))
	})
}

// RevokeUserSessions is for logout-all, password reset and security response.
// Authorization to revoke another user's sessions belongs to the caller.
func (a *Auth) RevokeUserSessions(ctx context.Context, userID, reason string) (int, error) {
	if userID == "" || strings.TrimSpace(reason) == "" {
		return 0, errors.New("user and reason required")
	}
	count := 0
	err := a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_sessions WHERE user_id=? AND status='active'`, userID).Scan(&count); e != nil {
			return e
		}
		if e := a.revokeUserTx(ctx, q, userID, reason, nowNS()); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(userID, "auth:user-revoke", userID))
	})
	return count, err
}

func (a *Auth) revokeUserTx(ctx context.Context, q sqlitedurable.Executor, userID, reason string, now int64) error {
	rows, e := q.QueryContext(ctx, `SELECT id FROM auth_sessions WHERE user_id=? AND status='active'`, userID)
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		ids = append(ids, id)
	}
	e = errors.Join(e, rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = a.revokeSessionTx(ctx, q, id, reason, now); e != nil {
			return e
		}
	}
	return nil
}
