package sqlitecore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

const (
	accessTTL       = 15 * time.Minute
	refreshTTL      = 30 * 24 * time.Hour
	maxUserSessions = 10
)

var (
	ErrAuthentication = errors.New("invalid or revoked credentials")
	ErrRefreshReuse   = errors.New("refresh-token reuse: entire session family revoked")
	ErrMFARequired    = errors.New("second factor required or invalid")
)

// Auth operates on the existing persistent Repository. The encryption key is
// supplied by the operator and is never written into the database.
type Auth struct {
	repo *Repository
	key  [32]byte
}

func (r *Repository) Auth(key []byte) (*Auth, error) {
	if len(key) != 32 {
		return nil, errors.New("32-byte independent MFA encryption key required")
	}
	a := &Auth{repo: r}
	copy(a.key[:], key)
	return a, nil
}

// Tokens contains bearer secrets returned exactly once, never stored in cleartext.
// Callers must transmit them only over an authenticated TLS channel.
type Tokens struct {
	SessionID        string    `json:"sessionId"`
	AccessToken      string    `json:"accessToken"`
	RefreshToken     string    `json:"refreshToken"`
	AccessExpiresAt  time.Time `json:"accessExpiresAt"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
}

type Principal struct {
	UserID, SessionID, RoleID string
	AuthEpoch                 int64
}

func bearer(prefix string) (string, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b[:])
	return raw, hashBearer(raw), nil
}
func hashBearer(raw string) string { h := sha256.Sum256([]byte(raw)); return hex.EncodeToString(h[:]) }
func validBearer(raw, prefix string) bool {
	if !strings.HasPrefix(raw, prefix) || len(raw) != len(prefix)+43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, prefix))
	return err == nil
}
func newID(prefix string) (string, error) {
	id, e := uid()
	if e != nil {
		return "", e
	}
	return prefix + id, nil
}

// LoginLocal verifies the same localpassword verifier as the PostgreSQL
// authentication path. Password and optional second factor are checked again
// inside the writer transaction, preventing password/role/epoch TOCTOU races.
// It never issues a session with a user-supplied MFA claim.
func (a *Auth) LoginLocal(ctx context.Context, email, password, factor, device string) (Tokens, error) {
	if email == "" || password == "" {
		return Tokens{}, ErrAuthentication
	}
	u, err := a.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Tokens{}, ErrAuthentication
		}
		return Tokens{}, err
	}
	if u.Status != "active" || !localpassword.Verify(password, u.PasswordHash) {
		return Tokens{}, ErrAuthentication
	}
	access, accessHash, err := bearer("nla_")
	if err != nil {
		return Tokens{}, err
	}
	refresh, refreshHash, err := bearer("nlr_")
	if err != nil {
		return Tokens{}, err
	}
	sid, err := newID("sess-")
	if err != nil {
		return Tokens{}, err
	}
	fid, err := newID("rtf-")
	if err != nil {
		return Tokens{}, err
	}
	if strings.TrimSpace(device) == "" {
		device = "desktop"
	}
	if len(device) > 96 || strings.ContainsAny(device, "\x00\r\n") {
		return Tokens{}, errors.New("invalid device name")
	}
	var result Tokens
	err = a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var currentHash, status string
		var epoch int64
		if e := q.QueryRowContext(ctx, `SELECT password_hash,status,auth_epoch FROM users WHERE id=?`, u.ID).Scan(&currentHash, &status, &epoch); e != nil {
			return e
		}
		if status != "active" || epoch < 1 || subtle.ConstantTimeCompare([]byte(currentHash), []byte(u.PasswordHash)) != 1 {
			return ErrAuthentication
		}
		methods := []string{"password"}
		var cipher []byte
		var mfaStatus string
		var lastStep int64
		e := q.QueryRowContext(ctx, `SELECT secret_ciphertext,status,last_step FROM mfa_totp WHERE user_id=?`, u.ID).Scan(&cipher, &mfaStatus, &lastStep)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && mfaStatus == "active" {
			if factor == "" {
				return ErrMFARequired
			}
			valid, e := a.checkSecondFactorTx(ctx, q, u.ID, cipher, factor, lastStep)
			if e != nil {
				return e
			}
			if !valid {
				return ErrMFARequired
			}
			methods = append(methods, "totp-or-recovery")
		}
		now := nowNS()
		accessExpiry := now + int64(accessTTL)
		refreshExpiry := now + int64(refreshTTL)
		raw, _ := json.Marshal(methods)
		if _, e = q.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,auth_epoch,device_id,status,auth_methods,created_at,last_seen_at,expires_at) VALUES(?,?,?,?,'active',?,?,?,?)`, sid, u.ID, epoch, device, string(raw), now, now, refreshExpiry); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO refresh_families(id,session_id,status,created_at) VALUES(?,?,'active',?)`, fid, sid, now); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,status,created_at,expires_at) VALUES(?,?,'current',?,?)`, refreshHash, fid, now, refreshExpiry); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO access_tokens(token_hash,session_id,issued_at,expires_at) VALUES(?,?,?,?)`, accessHash, sid, now, accessExpiry); e != nil {
			return e
		}
		// Oldest sessions are explicitly revoked before the new session is exposed.
		rows, e := q.QueryContext(ctx, `SELECT id FROM auth_sessions WHERE user_id=? AND status='active' ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?`, u.ID, maxUserSessions)
		if e != nil {
			return e
		}
		var old []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			old = append(old, id)
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for _, id := range old {
			if e = a.revokeSessionTx(ctx, q, id, "session-limit", now); e != nil {
				return e
			}
		}
		if _, e = q.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, now, u.ID); e != nil {
			return e
		}
		if e = recordAudit(ctx, q, audit(u.ID, "auth:login", sid)); e != nil {
			return e
		}
		result = Tokens{sid, access, refresh, ts(accessExpiry), ts(refreshExpiry)}
		return nil
	})
	return result, err
}

// ValidateAccess does a DB read for every decision. JWT-style stateless
// validation would miss revocation and is intentionally not offered here.
func (a *Auth) ValidateAccess(ctx context.Context, token string) (Principal, error) {
	if !validBearer(token, "nla_") {
		return Principal{}, ErrAuthentication
	}
	var p Principal
	err := a.repo.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var status, userStatus string
		var expires, revoked, sessionExpiry, epoch, currentEpoch int64
		e := q.QueryRowContext(ctx, `SELECT s.id,s.user_id,u.role_id,s.auth_epoch,u.auth_epoch,s.status,u.status,t.expires_at,t.revoked_at,s.expires_at
 FROM access_tokens t JOIN auth_sessions s ON s.id=t.session_id JOIN users u ON u.id=s.user_id WHERE t.token_hash=?`, hashBearer(token)).Scan(&p.SessionID, &p.UserID, &p.RoleID, &epoch, &currentEpoch, &status, &userStatus, &expires, &revoked, &sessionExpiry)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if e != nil {
			return e
		}
		if status != "active" || userStatus != "active" || epoch != currentEpoch || revoked != 0 || expires <= nowNS() || sessionExpiry <= nowNS() {
			return ErrAuthentication
		}
		p.AuthEpoch = epoch
		return nil
	})
	if err != nil {
		return Principal{}, err
	}
	return p, nil
}

// RotateRefresh is an atomic single-writer CAS. A consumed token triggers
// durable family compromise and dependent Minecraft token revocation even
// when the caller receives ErrRefreshReuse.
func (a *Auth) RotateRefresh(ctx context.Context, raw string) (Tokens, error) {
	if !validBearer(raw, "nlr_") {
		return Tokens{}, ErrAuthentication
	}
	access, accessHash, e := bearer("nla_")
	if e != nil {
		return Tokens{}, e
	}
	refresh, refreshHash, e := bearer("nlr_")
	if e != nil {
		return Tokens{}, e
	}
	var result Tokens
	var reused bool
	err := a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var family, sid, status, fStatus, sStatus, uStatus, userID string
		var expires, sExpires, epoch, currentEpoch int64
		e := q.QueryRowContext(ctx, `SELECT t.family_id,f.session_id,t.status,f.status,s.status,u.status,s.user_id,t.expires_at,s.expires_at,s.auth_epoch,u.auth_epoch
 FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id JOIN auth_sessions s ON s.id=f.session_id JOIN users u ON u.id=s.user_id WHERE t.token_hash=?`, hashBearer(raw)).Scan(&family, &sid, &status, &fStatus, &sStatus, &uStatus, &userID, &expires, &sExpires, &epoch, &currentEpoch)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if e != nil {
			return e
		}
		now := nowNS()
		if status == "consumed" && fStatus == "active" {
			if e = a.revokeSessionTx(ctx, q, sid, "refresh-reuse", now); e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, `UPDATE refresh_families SET status='compromised',revoked_at=? WHERE id=?`, now, family); e != nil {
				return e
			}
			if e = recordAudit(ctx, q, audit(userID, "auth:refresh-reuse", sid)); e != nil {
				return e
			}
			reused = true
			return nil
		}
		if status != "current" || fStatus != "active" || sStatus != "active" || uStatus != "active" || epoch != currentEpoch || expires <= now || sExpires <= now {
			return ErrAuthentication
		}
		res, e := q.ExecContext(ctx, `UPDATE refresh_tokens SET status='consumed',consumed_at=? WHERE token_hash=? AND status='current'`, now, hashBearer(raw))
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrAuthentication
		}
		accessExpiry := now + int64(accessTTL)
		refreshExpiry := sExpires
		if _, e = q.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,status,created_at,expires_at) VALUES(?,?,'current',?,?)`, refreshHash, family, now, refreshExpiry); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `UPDATE access_tokens SET revoked_at=? WHERE session_id=? AND revoked_at=0`, now, sid); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO access_tokens(token_hash,session_id,issued_at,expires_at) VALUES(?,?,?,?)`, accessHash, sid, now, accessExpiry); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at=? WHERE id=?`, now, sid); e != nil {
			return e
		}
		result = Tokens{sid, access, refresh, ts(accessExpiry), ts(refreshExpiry)}
		return recordAudit(ctx, q, audit(userID, "auth:refresh-rotate", sid))
	})
	if err != nil {
		return Tokens{}, err
	}
	if reused {
		return Tokens{}, ErrRefreshReuse
	}
	return result, nil
}

func audit(user, action, target string) model.AuditEvent {
	return model.AuditEvent{Actor: user, Action: action, Target: target}
}
