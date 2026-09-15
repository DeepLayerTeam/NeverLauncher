package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const (
	accessTokenTTL     = 15 * time.Minute
	refreshTokenTTL    = 30 * 24 * time.Hour
	maxSessionsPerUser = 10
)

type authSessionRecord struct {
	ID            string    `json:"id"`
	UserID        string    `json:"userId"`
	Email         string    `json:"email"`
	RoleID        string    `json:"roleId"`
	DeviceID      string    `json:"deviceId"`
	Device        string    `json:"device"`
	Status        string    `json:"status"`
	RefreshHash   string    `json:"-"`
	RefreshFamily string    `json:"refreshFamily"`
	CreatedAt     time.Time `json:"createdAt"`
	LastSeenAt    time.Time `json:"lastSeenAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	RevokedAt     time.Time `json:"revokedAt,omitempty"`
	RevokedReason string    `json:"revokedReason,omitempty"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"userAgent"`
}

type authSessionStore struct {
	mu       sync.Mutex
	sessions map[string]authSessionRecord
}

var errRefreshTokenInvalid = errors.New("refresh token недействителен")

func (s *authSessionStore) create(user model.User, r *http.Request, deviceID string) (authSessionRecord, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		deviceID = "admin-panel"
	}
	refreshToken, err := randomToken("nlr")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	record := authSessionRecord{
		ID:            fmt.Sprintf("sess-%d", now.UnixNano()),
		UserID:        user.ID,
		Email:         user.Email,
		RoleID:        user.RoleID,
		DeviceID:      deviceID,
		Device:        deviceID,
		Status:        "active",
		RefreshHash:   hashRefreshToken(refreshToken),
		RefreshFamily: fmt.Sprintf("rtf-%d", now.UnixNano()),
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(refreshTokenTTL),
		IP:            clientIP(r),
		UserAgent:     r.UserAgent(),
	}
	s.sessions[record.ID] = record
	s.enforceSessionLimitLocked(user.ID)
	return record, refreshToken, nil
}

func (s *authSessionStore) rotate(refreshToken string) (authSessionRecord, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	hash := hashRefreshToken(refreshToken)
	for id, record := range s.sessions {
		if record.RefreshHash != hash {
			continue
		}
		if record.Status != "active" || record.ExpiresAt.Before(now) {
			record.Status = "revoked"
			record.RevokedAt = now
			record.RevokedReason = "expired-or-inactive-refresh-token"
			s.sessions[id] = record
			return authSessionRecord{}, "", errRefreshTokenInvalid
		}
		newRefresh, err := randomToken("nlr")
		if err != nil {
			return authSessionRecord{}, "", err
		}
		record.RefreshHash = hashRefreshToken(newRefresh)
		record.LastSeenAt = now
		record.ExpiresAt = now.Add(refreshTokenTTL)
		s.sessions[id] = record
		return record, newRefresh, nil
	}
	return authSessionRecord{}, "", errRefreshTokenInvalid
}

func (s *authSessionStore) active(sessionID, userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[sessionID]
	if !ok || record.UserID != userID || record.Status != "active" || record.ExpiresAt.Before(time.Now().UTC()) {
		return false
	}
	record.LastSeenAt = time.Now().UTC()
	s.sessions[sessionID] = record
	return true
}

func (s *authSessionStore) revoke(sessionID, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	record.Status = "revoked"
	record.RevokedAt = time.Now().UTC()
	record.RevokedReason = firstNonEmpty(reason, "manual-revoke")
	s.sessions[sessionID] = record
	return true
}

func (s *authSessionStore) revokeUser(userID, reason string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	now := time.Now().UTC()
	for id, record := range s.sessions {
		if record.UserID != userID || record.Status != "active" {
			continue
		}
		record.Status = "revoked"
		record.RevokedAt = now
		record.RevokedReason = firstNonEmpty(reason, "user-session-revoke")
		s.sessions[id] = record
		count++
	}
	return count
}

func (s *authSessionStore) listByUser(userID string) []authSessionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]authSessionRecord, 0)
	for _, record := range s.sessions {
		if record.UserID == userID {
			items = append(items, sanitizeSessionRecord(record))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeenAt.After(items[j].LastSeenAt) })
	return items
}

func (s *authSessionStore) summary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	revoked := 0
	for _, record := range s.sessions {
		if record.Status == "active" && record.ExpiresAt.After(time.Now().UTC()) {
			active++
		} else {
			revoked++
		}
	}
	return map[string]any{"active": active, "revokedOrExpired": revoked, "total": len(s.sessions), "backend": "in-process-session-registry"}
}

func (s *authSessionStore) enforceSessionLimitLocked(userID string) {
	items := make([]authSessionRecord, 0)
	for _, record := range s.sessions {
		if record.UserID == userID && record.Status == "active" {
			items = append(items, record)
		}
	}
	if len(items) <= maxSessionsPerUser {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeenAt.Before(items[j].LastSeenAt) })
	for _, record := range items[:len(items)-maxSessionsPerUser] {
		record.Status = "revoked"
		record.RevokedAt = time.Now().UTC()
		record.RevokedReason = "max-sessions-per-user"
		s.sessions[record.ID] = record
	}
}

func sanitizeSessionRecord(record authSessionRecord) authSessionRecord {
	record.RefreshHash = ""
	return record
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(prefix string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
