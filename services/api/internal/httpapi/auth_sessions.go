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
	AuthMethods   []string  `json:"authMethods"`
	AuthStrength  string    `json:"authStrength"`
	AuthTime      time.Time `json:"authTime"`
	IdentityID    string    `json:"identityId,omitempty"`
	Provider      string    `json:"provider"`
	CreatedAt     time.Time `json:"createdAt"`
	LastSeenAt    time.Time `json:"lastSeenAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	RevokedAt     time.Time `json:"revokedAt,omitempty"`
	RevokedReason string    `json:"revokedReason,omitempty"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"userAgent"`
}

type refreshTokenRecord111 struct {
	Hash       string
	FamilyID   string
	SessionID  string
	Status     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

type refreshFamilyRecord111 struct {
	ID            string
	SessionID     string
	UserID        string
	Status        string
	CreatedAt     time.Time
	CompromisedAt time.Time
	RevokedAt     time.Time
	RevokedReason string
}

type authSessionStore struct {
	mu         sync.Mutex
	sessions   map[string]authSessionRecord
	tokens     map[string]refreshTokenRecord111 // key: SHA-256(refresh token)
	families   map[string]refreshFamilyRecord111
	persistent *authSessionPostgres111
}

var (
	errRefreshTokenInvalid       = errors.New("refresh token недействителен")
	errRefreshTokenReuseDetected = errors.New("обнаружено повторное использование refresh token")
)

func newAuthSessionStore111() *authSessionStore {
	return &authSessionStore{
		sessions: map[string]authSessionRecord{},
		tokens:   map[string]refreshTokenRecord111{},
		families: map[string]refreshFamilyRecord111{},
	}
}

func (s *authSessionStore) create(user model.User, r *http.Request, deviceID string) (authSessionRecord, string, error) {
	return s.createWithAuth(user, r, deviceID, []string{"password"}, "single-factor", time.Now().UTC(), "", "local")
}

func (s *authSessionStore) createWithAuth(user model.User, r *http.Request, deviceID string, methods []string, strength string, authTime time.Time, identityID, provider string) (authSessionRecord, string, error) {
	methods, strength, authTime, provider = normalizeSessionAuth117(methods, strength, authTime, provider)
	if s.persistent != nil {
		return s.persistent.createWithAuth(user, r, deviceID, methods, strength, authTime, identityID, provider)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMemoryMapsLocked111()

	now := time.Now().UTC()
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		deviceID = "admin-panel"
	}
	refreshToken, err := randomToken("nlr")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	familyID := fmt.Sprintf("rtf-%d", now.UnixNano())
	record := authSessionRecord{
		ID:            fmt.Sprintf("sess-%d", now.UnixNano()),
		UserID:        user.ID,
		Email:         user.Email,
		RoleID:        user.RoleID,
		DeviceID:      deviceID,
		Device:        deviceID,
		Status:        "active",
		RefreshHash:   hashRefreshToken(refreshToken),
		RefreshFamily: familyID,
		AuthMethods:   append([]string(nil), methods...),
		AuthStrength:  strength,
		AuthTime:      authTime,
		IdentityID:    strings.TrimSpace(identityID),
		Provider:      provider,
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(refreshTokenTTL),
		IP:            clientIP(r),
		UserAgent:     r.UserAgent(),
	}
	s.sessions[record.ID] = record
	s.families[familyID] = refreshFamilyRecord111{ID: familyID, SessionID: record.ID, UserID: user.ID, Status: "active", CreatedAt: now}
	s.tokens[record.RefreshHash] = refreshTokenRecord111{Hash: record.RefreshHash, FamilyID: familyID, SessionID: record.ID, Status: "current", CreatedAt: now, ExpiresAt: record.ExpiresAt}
	s.enforceSessionLimitLocked(user.ID)
	return record, refreshToken, nil
}

func (s *authSessionStore) rotate(refreshToken string) (authSessionRecord, string, error) {
	if s.persistent != nil {
		return s.persistent.rotate(refreshToken)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMemoryMapsLocked111()

	now := time.Now().UTC()
	hash := hashRefreshToken(refreshToken)
	token, ok := s.tokens[hash]
	if !ok {
		// Upgrade compatibility for an in-memory/snapshot session created before 0.11.1.
		for _, record := range s.sessions {
			if record.RefreshHash == hash {
				token = refreshTokenRecord111{Hash: hash, FamilyID: record.RefreshFamily, SessionID: record.ID, Status: "current", CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt}
				s.tokens[hash] = token
				if _, exists := s.families[record.RefreshFamily]; !exists {
					s.families[record.RefreshFamily] = refreshFamilyRecord111{ID: record.RefreshFamily, SessionID: record.ID, UserID: record.UserID, Status: "active", CreatedAt: record.CreatedAt}
				}
				ok = true
				break
			}
		}
	}
	if !ok {
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}
	if token.Status == "consumed" {
		s.compromiseFamilyLocked111(token.FamilyID, "refresh-token-reuse")
		return authSessionRecord{}, "", errRefreshTokenReuseDetected
	}
	if token.Status != "current" {
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}
	record, ok := s.sessions[token.SessionID]
	if !ok || record.Status != "active" || record.ExpiresAt.Before(now) || token.ExpiresAt.Before(now) {
		if ok {
			record.Status = "revoked"
			record.RevokedAt = now
			record.RevokedReason = "expired-or-inactive-refresh-token"
			s.sessions[record.ID] = record
		}
		return authSessionRecord{}, "", errRefreshTokenInvalid
	}
	newRefresh, err := randomToken("nlr")
	if err != nil {
		return authSessionRecord{}, "", err
	}
	newHash := hashRefreshToken(newRefresh)
	token.Status = "consumed"
	token.ConsumedAt = now
	s.tokens[hash] = token
	s.tokens[newHash] = refreshTokenRecord111{Hash: newHash, FamilyID: token.FamilyID, SessionID: token.SessionID, Status: "current", CreatedAt: now, ExpiresAt: now.Add(refreshTokenTTL)}
	record.RefreshHash = newHash
	record.LastSeenAt = now
	record.ExpiresAt = now.Add(refreshTokenTTL)
	s.sessions[record.ID] = record
	return record, newRefresh, nil
}

func (s *authSessionStore) active(sessionID, userID string) bool {
	if s.persistent != nil {
		return s.persistent.active(sessionID, userID)
	}
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
	if s.persistent != nil {
		return s.persistent.revoke(sessionID, reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	now := time.Now().UTC()
	record.Status = "revoked"
	record.RevokedAt = now
	record.RevokedReason = firstNonEmpty(reason, "manual-revoke")
	s.sessions[sessionID] = record
	s.revokeFamilyLocked111(record.RefreshFamily, record.RevokedReason, now)
	return true
}

func (s *authSessionStore) revokeUser(userID, reason string) int {
	if s.persistent != nil {
		return s.persistent.revokeUser(userID, reason)
	}
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
		s.revokeFamilyLocked111(record.RefreshFamily, record.RevokedReason, now)
		count++
	}
	return count
}

func (s *authSessionStore) listByUser(userID string) []authSessionRecord {
	if s.persistent != nil {
		return s.persistent.listByUser(userID)
	}
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

func (s *authSessionStore) get(sessionID, userID string) (authSessionRecord, bool) {
	if s.persistent != nil {
		return s.persistent.get(sessionID, userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok || rec.UserID != userID || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, false
	}
	return sanitizeSessionRecord(rec), true
}

func (s *authSessionStore) stepUp(sessionID, userID string, methods []string, strength string, authTime time.Time) (authSessionRecord, error) {
	methods, strength, authTime, _ = normalizeSessionAuth117(methods, strength, authTime, "local")
	if s.persistent != nil {
		return s.persistent.stepUp(sessionID, userID, methods, strength, authTime)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok || rec.UserID != userID || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errAuthRequired
	}
	rec.AuthMethods = mergeAuthMethods117(rec.AuthMethods, methods...)
	if authStrengthLevel117(strength) > authStrengthLevel117(rec.AuthStrength) {
		rec.AuthStrength = strength
	}
	rec.AuthTime = authTime
	rec.LastSeenAt = time.Now().UTC()
	s.sessions[rec.ID] = rec
	return sanitizeSessionRecord(rec), nil
}

func normalizeSessionAuth117(methods []string, strength string, authTime time.Time, provider string) ([]string, string, time.Time, string) {
	methods = mergeAuthMethods117(nil, methods...)
	if len(methods) == 0 {
		methods = []string{"unknown"}
	}
	if authStrengthLevel117(strength) < 0 {
		strength = "single-factor"
	}
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "local"
	}
	return methods, strength, authTime.UTC(), provider
}

func mergeAuthMethods117(existing []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(extra))
	out := make([]string, 0, len(existing)+len(extra))
	for _, raw := range append(append([]string(nil), existing...), extra...) {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func authStrengthLevel117(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "single-factor":
		return 0
	case "mfa":
		return 1
	case "phishing-resistant":
		return 2
	default:
		return -1
	}
}

func (s *authSessionStore) summary() map[string]any {
	if s.persistent != nil {
		return s.persistent.summary()
	}
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
	return map[string]any{"active": active, "revokedOrExpired": revoked, "total": len(s.sessions), "backend": "in-process-dev-session-registry", "reuseDetection": "token-family"}
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
		s.revokeFamilyLocked111(record.RefreshFamily, record.RevokedReason, record.RevokedAt)
	}
}

func (s *authSessionStore) ensureMemoryMapsLocked111() {
	if s.sessions == nil {
		s.sessions = map[string]authSessionRecord{}
	}
	if s.tokens == nil {
		s.tokens = map[string]refreshTokenRecord111{}
	}
	if s.families == nil {
		s.families = map[string]refreshFamilyRecord111{}
	}
}

func (s *authSessionStore) compromiseFamilyLocked111(familyID, reason string) {
	now := time.Now().UTC()
	family := s.families[familyID]
	family.Status = "compromised"
	family.CompromisedAt = now
	family.RevokedReason = reason
	s.families[familyID] = family
	if record, ok := s.sessions[family.SessionID]; ok {
		record.Status = "revoked"
		record.RevokedAt = now
		record.RevokedReason = reason
		s.sessions[record.ID] = record
	}
	for hash, token := range s.tokens {
		if token.FamilyID == familyID {
			token.Status = "revoked"
			s.tokens[hash] = token
		}
	}
}

func (s *authSessionStore) revokeFamilyLocked111(familyID, reason string, now time.Time) {
	if familyID == "" {
		return
	}
	family := s.families[familyID]
	family.Status = "revoked"
	family.RevokedAt = now
	family.RevokedReason = reason
	s.families[familyID] = family
	for hash, token := range s.tokens {
		if token.FamilyID == familyID && token.Status != "revoked" {
			token.Status = "revoked"
			s.tokens[hash] = token
		}
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
