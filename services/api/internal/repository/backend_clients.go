package repository

import (
	"context"
	"time"
)

// Minecraft clients are active authorization sessions recently seen by the API.
// A session does not prove the game process has a live TCP connection.
type BackendMinecraftClient0289 struct {
	SessionID       string    `json:"sessionId"`
	UserID          string    `json:"userId"`
	ProfileUUID     string    `json:"profileUuid"`
	LauncherVersion string    `json:"launcherVersion"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type BackendMinecraftClientStore0289 interface {
	ListRecentMinecraftClients0289(context.Context, time.Time, time.Duration) ([]BackendMinecraftClient0289, error)
}

func (r *SQLRepository) ListRecentMinecraftClients0289(ctx context.Context, now time.Time, age time.Duration) ([]BackendMinecraftClient0289, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,user_id,profile_uuid,launcher_version,last_seen_at,expires_at
 FROM minecraft_sessions WHERE status='active' AND revoked_at IS NULL AND expires_at>$1 AND last_seen_at BETWEEN $2 AND $1
 ORDER BY last_seen_at DESC LIMIT 100`, now, now.Add(-age))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BackendMinecraftClient0289, 0)
	for rows.Next() {
		var it BackendMinecraftClient0289
		if err = rows.Scan(&it.SessionID, &it.UserID, &it.ProfileUUID, &it.LauncherVersion, &it.LastSeenAt, &it.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
func (r *MemoryRepository) ListRecentMinecraftClients0289(ctx context.Context, now time.Time, age time.Duration) ([]BackendMinecraftClient0289, error) {
	r.minecraftMu.Lock()
	defer r.minecraftMu.Unlock()
	out := make([]BackendMinecraftClient0289, 0)
	for _, it := range r.minecraftSessions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if it.Status != "active" || !it.RevokedAt.IsZero() || !it.ExpiresAt.After(now) || it.LastSeenAt.Before(now.Add(-age)) || it.LastSeenAt.After(now) {
			continue
		}
		out = append(out, BackendMinecraftClient0289{SessionID: it.ID, UserID: it.UserID, ProfileUUID: it.ProfileUUID, LauncherVersion: it.LauncherVersion, LastSeenAt: it.LastSeenAt, ExpiresAt: it.ExpiresAt})
		if len(out) == 100 {
			break
		}
	}
	return out, nil
}
