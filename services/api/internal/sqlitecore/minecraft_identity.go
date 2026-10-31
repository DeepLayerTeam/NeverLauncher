package sqlitecore

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

var mcName = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var mcUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// SaveMinecraftIdentity binds an existing canonical user to one immutable UUID.
// It derives a new UUID from mutable email, display name or launcher name.
func (a *Auth) SaveMinecraftIdentity(ctx context.Context, p model.MinecraftProfile, actor string) (model.MinecraftProfile, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.UUID = strings.ToLower(strings.TrimSpace(p.UUID))
	if !mcName.MatchString(p.Name) || !mcUUID.MatchString(p.UUID) || p.UserID == "" || actor == "" {
		return p, errors.New("valid Minecraft name, UUID, user and actor required")
	}
	p.Issuer = strings.ToLower(strings.TrimSpace(p.Issuer))
	p.Realm = strings.ToLower(strings.TrimSpace(p.Realm))
	p.Subject = strings.TrimSpace(p.Subject)
	p.IdentityVersion = strings.TrimSpace(p.IdentityVersion)
	if p.Issuer == "" {
		p.Issuer = "launcher"
	}
	if p.Realm == "" {
		p.Realm = "local"
	}
	if p.Subject == "" {
		p.Subject = p.UUID
	}
	if p.IdentityVersion == "" {
		p.IdentityVersion = "independent-v1"
	}
	e := a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var oldUUID, oldIssuer, oldRealm, oldSubject string
		var created int64
		e := q.QueryRowContext(ctx, `SELECT uuid,issuer,realm,subject,created_at FROM minecraft_profiles WHERE user_id=?`, p.UserID).Scan(&oldUUID, &oldIssuer, &oldRealm, &oldSubject, &created)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && (oldUUID != p.UUID || oldIssuer != p.Issuer || oldRealm != p.Realm || oldSubject != p.Subject) {
			return ErrImmutable
		}
		now := nowNS()
		if errors.Is(e, sql.ErrNoRows) {
			created = now
		}
		// Reject assigning the identity of an inactive user to a live token later.
		var status string
		if e = q.QueryRowContext(ctx, `SELECT status FROM users WHERE id=?`, p.UserID).Scan(&status); e != nil {
			return notFound(e)
		}
		if status != "active" {
			return ErrAuthentication
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
 ON CONFLICT(user_id) DO UPDATE SET name=excluded.name,realm=excluded.realm,identity_version=excluded.identity_version,updated_at=excluded.updated_at`, p.UserID, p.UUID, p.Name, p.Issuer, p.Realm, p.Subject, p.IdentityVersion, created, now); e != nil {
			return conflict(e)
		}
		return recordAudit(ctx, q, audit(actor, "minecraft:identity-save", p.UUID))
	})
	if e != nil {
		return model.MinecraftProfile{}, e
	}
	return a.MinecraftIdentity(ctx, p.UserID)
}
func (a *Auth) MinecraftIdentity(ctx context.Context, userID string) (p model.MinecraftProfile, e error) {
	e = a.repo.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var created, updated int64
		er := q.QueryRowContext(ctx, `SELECT user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at FROM minecraft_profiles WHERE user_id=?`, userID).Scan(&p.UserID, &p.UUID, &p.Name, &p.Issuer, &p.Realm, &p.Subject, &p.IdentityVersion, &created, &updated)
		if er != nil {
			return notFound(er)
		}
		p.CreatedAt, p.UpdatedAt = ts(created), ts(updated)
		return nil
	})
	return
}

// IssueMinecraftSession requires the current access token, joins the
// canonical profile and writes only the hash of the new bearer. Password or
// disabled user changes instantly invalidate the token via auth_epoch.
func (a *Auth) IssueMinecraftSession(ctx context.Context, Access string, ttl time.Duration) (string, string, error) {
	if ttl <= 0 || ttl > 24*time.Hour {
		return "", "", errors.New("Minecraft token TTL must be <=24h")
	}
	principal, e := a.ValidateAccess(ctx, Access)
	if e != nil {
		return "", "", e
	}
	raw, hash, e := bearer("nlm_")
	if e != nil {
		return "", "", e
	}
	sid, e := newID("mcs-")
	if e != nil {
		return "", "", e
	}
	e = a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var uuid, status string
		var epoch, currentEpoch int64
		var expires int64
		er := q.QueryRowContext(ctx, `SELECT p.uuid,s.status,s.auth_epoch,u.auth_epoch,s.expires_at FROM auth_sessions s JOIN users u ON u.id=s.user_id JOIN minecraft_profiles p ON p.user_id=u.id WHERE s.id=? AND s.user_id=? AND u.status='active'`, principal.SessionID, principal.UserID).Scan(&uuid, &status, &epoch, &currentEpoch, &expires)
		if errors.Is(er, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if er != nil {
			return er
		}
		now := nowNS()
		if status != "active" || epoch != currentEpoch || expires <= now {
			return ErrAuthentication
		}
		var accessExpiry, accessRevoked int64
		if er = q.QueryRowContext(ctx, `SELECT expires_at,revoked_at FROM access_tokens WHERE token_hash=? AND session_id=?`, hashBearer(Access), principal.SessionID).Scan(&accessExpiry, &accessRevoked); er != nil {
			return ErrAuthentication
		}
		if accessRevoked != 0 || accessExpiry <= now {
			return ErrAuthentication
		}
		if _, er = q.ExecContext(ctx, `INSERT INTO minecraft_sessions(id,user_id,session_id,profile_uuid,access_hash,status,created_at,expires_at) VALUES(?,?,?,?,?,'active',?,?)`, sid, principal.UserID, principal.SessionID, uuid, hash, now, now+int64(ttl)); er != nil {
			return er
		}
		return recordAudit(ctx, q, audit(principal.UserID, "minecraft:session-created", sid))
	})
	if e != nil {
		return "", "", e
	}
	return sid, raw, nil
}
func (a *Auth) ValidateMinecraftSession(ctx context.Context, raw string) (model.MinecraftProfile, error) {
	if !validBearer(raw, "nlm_") {
		return model.MinecraftProfile{}, ErrAuthentication
	}
	var p model.MinecraftProfile
	e := a.repo.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var mcStatus, sessionStatus, userStatus string
		var expire, sExpire, epoch, currentEpoch int64
		er := q.QueryRowContext(ctx, `SELECT p.user_id,p.uuid,p.name,p.issuer,p.realm,p.subject,p.identity_version,m.status,s.status,u.status,m.expires_at,s.expires_at,s.auth_epoch,u.auth_epoch
 FROM minecraft_sessions m JOIN minecraft_profiles p ON p.uuid=m.profile_uuid JOIN auth_sessions s ON s.id=m.session_id JOIN users u ON u.id=m.user_id
 WHERE m.access_hash=? AND m.user_id=p.user_id AND s.user_id=m.user_id`, hashBearer(raw)).Scan(&p.UserID, &p.UUID, &p.Name, &p.Issuer, &p.Realm, &p.Subject, &p.IdentityVersion, &mcStatus, &sessionStatus, &userStatus, &expire, &sExpire, &epoch, &currentEpoch)
		if errors.Is(er, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if er != nil {
			return er
		}
		now := nowNS()
		if mcStatus != "active" || sessionStatus != "active" || userStatus != "active" || expire <= now || sExpire <= now || epoch != currentEpoch {
			return ErrAuthentication
		}
		return nil
	})
	if e != nil {
		return model.MinecraftProfile{}, e
	}
	return p, nil
}

// RevokeMinecraftSession invalidates one Minecraft bearer without revoking the
// parent session. Session ownership is checked in the same transaction.
func (a *Auth) RevokeMinecraftSession(ctx context.Context, userID, id, reason string) error {
	if userID == "" || id == "" || strings.TrimSpace(reason) == "" {
		return errors.New("owner/session/reason required")
	}
	return a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var owner string
		if e := q.QueryRowContext(ctx, `SELECT user_id FROM minecraft_sessions WHERE id=?`, id).Scan(&owner); e != nil {
			return notFound(e)
		}
		if owner != userID {
			return ErrAuthentication
		}
		if _, e := q.ExecContext(ctx, `UPDATE minecraft_sessions SET status='revoked',revoked_at=?,revoked_reason=? WHERE id=? AND status='active'`, nowNS(), reason, id); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(userID, "minecraft:session-revoked", id))
	})
}
