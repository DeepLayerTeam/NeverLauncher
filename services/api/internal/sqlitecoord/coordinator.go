// Package sqlitecoord is the durable, fail-closed Redis-free coordinator for
// exactly one API process. It uses the same supported WAL filesystem contract
// as sqlitedurable and intentionally does not implement distributed HA.
package sqlitecoord

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/ratelimit"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/serverbridgeha"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

var ErrInvalid = errors.New("sqlite coordinator: invalid arguments")

// Coordinator owns exactly one local SQLite database and lock for its lifetime.
// A second process cannot open the same database through sqlitedurable.Open.
// The store must be closed on orderly application shutdown.
type Coordinator struct{ db *sqlitedurable.Store }

var _ ratelimit.Limiter = (*Coordinator)(nil)
var _ serverbridgeha.Coordinator = (*Coordinator)(nil)

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS coord_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coord_channels (
 server_id TEXT NOT NULL, runtime_id TEXT NOT NULL, channel_id TEXT NOT NULL,
 replica_id TEXT NOT NULL, backend_address TEXT NOT NULL,
 resume_after INTEGER NOT NULL CHECK(resume_after>=0), expires_at INTEGER NOT NULL,
 PRIMARY KEY(server_id,runtime_id,channel_id));
CREATE INDEX IF NOT EXISTS coord_channels_expiry ON coord_channels(expires_at);
CREATE TABLE IF NOT EXISTS coord_leases (
 server_id TEXT NOT NULL, command_id TEXT NOT NULL, owner_hash TEXT NOT NULL,
 token_hash TEXT NOT NULL, fence INTEGER NOT NULL CHECK(fence>=1),
 expires_at INTEGER NOT NULL, PRIMARY KEY(server_id,command_id));
CREATE INDEX IF NOT EXISTS coord_leases_expiry ON coord_leases(expires_at);
CREATE TABLE IF NOT EXISTS coord_lease_tokens (
 server_id TEXT NOT NULL, command_id TEXT NOT NULL, token_hash TEXT NOT NULL,
 fence INTEGER NOT NULL CHECK(fence>=1), PRIMARY KEY(server_id,command_id,token_hash));
CREATE TABLE IF NOT EXISTS coord_limits (
 key_hash TEXT PRIMARY KEY, count INTEGER NOT NULL CHECK(count>=1),
 resets_at INTEGER NOT NULL, last_updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS coord_limits_expiry ON coord_limits(resets_at);
`

func Open(ctx context.Context, path string) (_ *Coordinator, err error) {
	db, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path, Readers: 2})
	if err != nil {
		return nil, fmt.Errorf("sqlite coordinator open: %w", err)
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	c := &Coordinator{db: db}
	err = db.Write(ctx, func(q sqlitedurable.Executor) error {
		// Statements deliberately execute inside one BEGIN IMMEDIATE transaction.
		for _, stmt := range strings.Split(schema, ";\n") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, e := q.ExecContext(ctx, stmt); e != nil {
				return fmt.Errorf("coordinator DDL: %w", e)
			}
		}
		_, e := q.ExecContext(ctx, "INSERT INTO coord_meta(key,value) VALUES('version',?) ON CONFLICT(key) DO NOTHING", schemaVersion)
		if e != nil {
			return e
		}
		var v int
		if e = q.QueryRowContext(ctx, "SELECT value FROM coord_meta WHERE key='version'").Scan(&v); e != nil {
			return e
		}
		if v != schemaVersion {
			return fmt.Errorf("coordinator schema version %d unsupported", v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = c.Health(ctx); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Coordinator) Close() error    { return c.db.Close() }
func (c *Coordinator) Backend() string { return "sqlite-wal-single-node" }
func (c *Coordinator) Health(ctx context.Context) error {
	// Health must prove the writer is available; a read-only DB is not healthy.
	return c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		var v int
		if err := q.QueryRowContext(ctx, "SELECT value FROM coord_meta WHERE key='version'").Scan(&v); err != nil {
			return err
		}
		if v != schemaVersion {
			return fmt.Errorf("coordinator incompatible schema %d", v)
		}
		_, err := q.ExecContext(ctx, "UPDATE coord_meta SET value=value WHERE key='version'")
		return err
	})
}

func validatePart(parts ...string) error {
	for _, p := range parts {
		if len(p) < 1 || len(p) > 256 || strings.TrimSpace(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return ErrInvalid
		}
	}
	return nil
}
func digest(p string) string   { h := sha256.Sum256([]byte(p)); return hex.EncodeToString(h[:]) }
func millis(t time.Time) int64 { return t.UnixMilli() }
func leaseTTL(ttl time.Duration) time.Duration {
	if ttl < 5*time.Second {
		return 5 * time.Second
	}
	if ttl > 5*time.Minute {
		return 5 * time.Minute
	}
	return ttl
}

func (c *Coordinator) TouchChannel(ctx context.Context, p serverbridgeha.ChannelPresence, ttl time.Duration) error {
	if e := validatePart(p.ReplicaID, p.ServerID, p.RuntimeID, p.ChannelID, p.BackendAddress); e != nil {
		return e
	}
	if p.ResumeAfter < 0 {
		return ErrInvalid
	}
	now := time.Now().UTC()
	expires := millis(now.Add(leaseTTL(ttl)))
	return c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		// Do not let an out-of-order touch rewind a live channel cursor.
		res, e := q.ExecContext(ctx, `INSERT INTO coord_channels(server_id,runtime_id,channel_id,replica_id,backend_address,resume_after,expires_at)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(server_id,runtime_id,channel_id) DO UPDATE SET
replica_id=excluded.replica_id,backend_address=excluded.backend_address,
resume_after=excluded.resume_after,expires_at=excluded.expires_at
WHERE coord_channels.expires_at<=? OR coord_channels.resume_after<=excluded.resume_after`,
			p.ServerID, p.RuntimeID, p.ChannelID, p.ReplicaID, p.BackendAddress, p.ResumeAfter, expires, millis(now))
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return errors.New("coordinator: stale channel cursor")
		}
		return nil
	})
}

// AcquireCommandLease never reuses an old token, including after expiry or
// release. Fencing high-water marks and the token tombstone table persist.
func (c *Coordinator) AcquireCommandLease(ctx context.Context, serverID, commandID, owner, token string, ttl time.Duration) (bool, error) {
	if e := validatePart(serverID, commandID, owner, token); e != nil {
		return false, e
	}
	key := digest(token)
	own := digest(owner)
	now := millis(time.Now().UTC())
	expires := millis(time.Now().UTC().Add(leaseTTL(ttl)))
	acquired := false
	err := c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		var prevOwner, prevToken string
		var fence, until int64
		e := q.QueryRowContext(ctx, "SELECT owner_hash,token_hash,fence,expires_at FROM coord_leases WHERE server_id=? AND command_id=?", serverID, commandID).Scan(&prevOwner, &prevToken, &fence, &until)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && until > now {
			if prevOwner != own || prevToken != key {
				return nil
			}
			// Only the current holder can extend a live lease.
			_, e = q.ExecContext(ctx, "UPDATE coord_leases SET expires_at=? WHERE server_id=? AND command_id=?", expires, serverID, commandID)
			acquired = e == nil
			return e
		}
		// A released or expired token cannot acquire again; a fresh token must
		// accompany each new ownership epoch even if the owner string is equal.
		var exists int
		e = q.QueryRowContext(ctx, "SELECT 1 FROM coord_lease_tokens WHERE server_id=? AND command_id=? AND token_hash=?", serverID, commandID, key).Scan(&exists)
		if e == nil {
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if fence == math.MaxInt64 {
			return errors.New("coordinator: fence counter exhausted")
		}
		fence++
		if _, e = q.ExecContext(ctx, "INSERT INTO coord_lease_tokens(server_id,command_id,token_hash,fence) VALUES(?,?,?,?)", serverID, commandID, key, fence); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO coord_leases(server_id,command_id,owner_hash,token_hash,fence,expires_at)
VALUES(?,?,?,?,?,?) ON CONFLICT(server_id,command_id) DO UPDATE SET
owner_hash=excluded.owner_hash,token_hash=excluded.token_hash,fence=excluded.fence,expires_at=excluded.expires_at`, serverID, commandID, own, key, fence, expires)
		acquired = e == nil
		return e
	})
	return acquired, err
}
func (c *Coordinator) VerifyCommandLease(ctx context.Context, serverID, commandID, owner, token string) (bool, error) {
	if e := validatePart(serverID, commandID, owner, token); e != nil {
		return false, e
	}
	ok := false
	err := c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		var own, tok string
		var expiry int64
		e := q.QueryRowContext(ctx, "SELECT owner_hash,token_hash,expires_at FROM coord_leases WHERE server_id=? AND command_id=?", serverID, commandID).Scan(&own, &tok, &expiry)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		ok = own == digest(owner) && tok == digest(token) && expiry > millis(time.Now().UTC())
		return nil
	})
	return ok, err
}
func (c *Coordinator) ReleaseCommandLease(ctx context.Context, serverID, commandID, owner, token string) error {
	if e := validatePart(serverID, commandID, owner, token); e != nil {
		return e
	}
	return c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `UPDATE coord_leases SET owner_hash='',token_hash='',expires_at=0
WHERE server_id=? AND command_id=? AND owner_hash=? AND token_hash=? AND expires_at>?`, serverID, commandID, digest(owner), digest(token), millis(time.Now().UTC()))
		return e
	})
}

// Allow implements a durable fixed window. Like the Redis implementation,
// requests that exceed the budget are counted. Invalid budgets fail closed.
func (c *Coordinator) Allow(ctx context.Context, key string, limit int, window time.Duration) (ratelimit.Result, error) {
	if e := validatePart(key); e != nil {
		return ratelimit.Result{}, e
	}
	if limit <= 0 || window < time.Millisecond || window > 24*time.Hour {
		return ratelimit.Result{}, ErrInvalid
	}
	now := millis(time.Now().UTC())
	// Reject huge conversion overflows; UnixMillis addition must remain safe.
	if window.Milliseconds() > math.MaxInt64-now {
		return ratelimit.Result{}, ErrInvalid
	}
	reset := now + window.Milliseconds()
	count, expires := int64(0), int64(0)
	err := c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `INSERT INTO coord_limits(key_hash,count,resets_at,last_updated) VALUES(?,1,?,?)
ON CONFLICT(key_hash) DO UPDATE SET
count=CASE WHEN coord_limits.resets_at<=? THEN 1 WHEN coord_limits.count<9223372036854775807 THEN coord_limits.count+1 ELSE coord_limits.count END,
resets_at=CASE WHEN coord_limits.resets_at<=? THEN excluded.resets_at ELSE coord_limits.resets_at END,
last_updated=excluded.last_updated`, digest(key), reset, now, now, now)
		if e != nil {
			return e
		}
		return q.QueryRowContext(ctx, "SELECT count,resets_at FROM coord_limits WHERE key_hash=?", digest(key)).Scan(&count, &expires)
	})
	if err != nil {
		return ratelimit.Result{}, err
	}
	remaining := 0
	if count < int64(limit) {
		remaining = limit - int(count)
	}
	resetAfter := time.Duration(expires-now) * time.Millisecond
	if resetAfter < 0 {
		resetAfter = 0
	}
	return ratelimit.Result{Allowed: count <= int64(limit), Limit: limit, Remaining: remaining, ResetAfter: resetAfter}, nil
}

// Prune only removes expired ephemeral channel and counter data. Lease rows
// and token tombstones are retained permanently to prevent ABA and token replay.
func (c *Coordinator) Prune(ctx context.Context) (int64, error) {
	var n int64
	err := c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, name := range []string{"coord_channels", "coord_limits"} {
			column := "expires_at"
			if name == "coord_limits" {
				column = "resets_at"
			}
			result, e := q.ExecContext(ctx, "DELETE FROM "+name+" WHERE "+column+"<=?", millis(time.Now().UTC()))
			if e != nil {
				return e
			}
			affected, e := result.RowsAffected()
			if e != nil {
				return e
			}
			n += affected
		}
		return nil
	})
	return n, err
}

// Channel retrieves only unexpired presence and is useful to a local worker
// recovering a channel after a process restart.
func (c *Coordinator) Channel(ctx context.Context, serverID, runtimeID, channelID string) (p serverbridgeha.ChannelPresence, found bool, err error) {
	if err = validatePart(serverID, runtimeID, channelID); err != nil {
		return p, false, err
	}
	p.ServerID, p.RuntimeID, p.ChannelID = serverID, runtimeID, channelID
	err = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		e := q.QueryRowContext(ctx, `SELECT replica_id,backend_address,resume_after FROM coord_channels
WHERE server_id=? AND runtime_id=? AND channel_id=? AND expires_at>?`, serverID, runtimeID, channelID, millis(time.Now().UTC())).Scan(&p.ReplicaID, &p.BackendAddress, &p.ResumeAfter)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	return
}
