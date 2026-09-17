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
	ID               string    `json:"id"`
	UserID           string    `json:"userId"`
	Email            string    `json:"email"`
	RoleID           string    `json:"roleId"`
	DeviceID         string    `json:"deviceId"`
	Device           string    `json:"device"`
	Status           string    `json:"status"`
	RefreshHash      string    `json:"-"`
	RefreshFamily    string    `json:"refreshFamily"`
	AuthMethods      []string  `json:"authMethods"`
	AuthStrength     string    `json:"authStrength"`
	AuthTime         time.Time `json:"authTime"`
	IdentityID       string    `json:"identityId,omitempty"`
	Provider         string    `json:"provider"`
	CreatedAt        time.Time `json:"createdAt"`
	LastSeenAt       time.Time `json:"lastSeenAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RevokedAt        time.Time `json:"revokedAt,omitempty"`
	RevokedReason    string    `json:"revokedReason,omitempty"`
	IP               string    `json:"ip"`
	UserAgent        string    `json:"userAgent"`
	LastIP           string    `json:"lastIp"`
	LastUserAgent    string    `json:"lastUserAgent"`
	RiskState        string    `json:"riskState"`
	RiskReasons      []string  `json:"riskReasons"`
	RiskUpdatedAt    time.Time `json:"riskUpdatedAt,omitempty"`
	DeviceRenamedAt  time.Time `json:"deviceRenamedAt,omitempty"`
	TrustedDeviceID  string    `json:"trustedDeviceId,omitempty"`
	DeviceTrustState string    `json:"deviceTrustState"`
	DeviceVerifiedAt time.Time `json:"deviceVerifiedAt,omitempty"`
	BindingEpoch     int64     `json:"bindingEpoch"`
	RiskScore        int       `json:"riskScore"`
	RiskAction       string    `json:"riskAction"`
	RiskEvaluatedAt  time.Time `json:"riskEvaluatedAt,omitempty"`
	Current          bool      `json:"current,omitempty"`
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
		ID:               fmt.Sprintf("sess-%d", now.UnixNano()),
		UserID:           user.ID,
		Email:            user.Email,
		RoleID:           user.RoleID,
		DeviceID:         deviceID,
		Device:           deviceID,
		Status:           "active",
		RefreshHash:      hashRefreshToken(refreshToken),
		RefreshFamily:    familyID,
		AuthMethods:      append([]string(nil), methods...),
		AuthStrength:     strength,
		AuthTime:         authTime,
		IdentityID:       strings.TrimSpace(identityID),
		Provider:         provider,
		CreatedAt:        now,
		LastSeenAt:       now,
		ExpiresAt:        now.Add(refreshTokenTTL),
		IP:               clientIP(r),
		UserAgent:        r.UserAgent(),
		LastIP:           clientIP(r),
		LastUserAgent:    r.UserAgent(),
		RiskState:        "normal",
		RiskReasons:      []string{},
		BindingEpoch:     1,
		RiskScore:        0,
		RiskAction:       "allow",
		RiskEvaluatedAt:  now,
		DeviceTrustState: "unverified",
	}
	s.sessions[record.ID] = record
	s.families[familyID] = refreshFamilyRecord111{ID: familyID, SessionID: record.ID, UserID: user.ID, Status: "active", CreatedAt: now}
	s.tokens[record.RefreshHash] = refreshTokenRecord111{Hash: record.RefreshHash, FamilyID: familyID, SessionID: record.ID, Status: "current", CreatedAt: now, ExpiresAt: record.ExpiresAt}
	s.enforceSessionLimitLocked(user.ID)
	return record, refreshToken, nil
}

func (s *authSessionStore) rotate(refreshToken string, r ...*http.Request) (authSessionRecord, string, error) {
	if s.persistent != nil {
		record, token, err := s.persistent.rotate(refreshToken)
		if err == nil && len(r) > 0 && r[0] != nil {
			if observed, ok := s.persistent.observe118(record.ID, record.UserID, r[0]); ok {
				record = observed
			}
		}
		return record, token, err
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
	if len(r) > 0 && r[0] != nil {
		applySessionObservation118(&record, clientIP(r[0]), r[0].UserAgent(), now)
	}
	s.sessions[record.ID] = record
	return sanitizeSessionRecord(record), newRefresh, nil
}

func (s *authSessionStore) active(sessionID, userID string) bool {
	_, ok := s.observe(sessionID, userID, nil)
	return ok
}

func (s *authSessionStore) observe(sessionID, userID string, r *http.Request) (authSessionRecord, bool) {
	if s.persistent != nil {
		return s.persistent.observe118(sessionID, userID, r)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[sessionID]
	if !ok || record.UserID != userID || record.Status != "active" || record.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, false
	}
	now := time.Now().UTC()
	if r != nil {
		applySessionObservation118(&record, clientIP(r), r.UserAgent(), now)
	}
	record.LastSeenAt = now
	s.sessions[sessionID] = record
	return sanitizeSessionRecord(record), true
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
		return s.persistent.listByUser118(userID)
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
		return s.persistent.get118(sessionID, userID)
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
	now := time.Now().UTC()
	clearStepUpRisk0126(&rec, now)
	rec.LastSeenAt = now
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
		return s.persistent.summary118()
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
	elevated := 0
	compromised := 0
	for _, record := range s.sessions {
		switch record.RiskState {
		case "elevated":
			elevated++
		case "compromised":
			compromised++
		}
	}
	return map[string]any{"active": active, "revokedOrExpired": revoked, "total": len(s.sessions), "backend": "in-process-dev-session-registry", "reuseDetection": "token-family", "risk": map[string]int{"elevated": elevated, "compromised": compromised}}
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
		record.RiskState = "compromised"
		record.RiskReasons = mergeRiskReasons118(record.RiskReasons, reason)
		record.RiskScore = 100
		record.RiskAction = "revoke"
		record.RiskEvaluatedAt = now
		record.RiskUpdatedAt = now
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

func (s *authSessionStore) bindTrustedDevice121(sessionID, userID, deviceID string, verifiedAt time.Time) (authSessionRecord, error) {
	if s.persistent != nil {
		return s.persistent.bindTrustedDevice121(sessionID, userID, deviceID, verifiedAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok || rec.UserID != userID || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errSessionNotFound118
	}
	rec.TrustedDeviceID = strings.TrimSpace(deviceID)
	rec.DeviceTrustState = "verified"
	rec.DeviceVerifiedAt = verifiedAt.UTC()
	if rec.BindingEpoch < 1 {
		rec.BindingEpoch = 1
	}
	rec.BindingEpoch++
	rec.LastSeenAt = time.Now().UTC()
	s.sessions[sessionID] = rec
	return sanitizeSessionRecord(rec), nil
}

func (s *authSessionStore) revokeTrustedDevice121(userID, deviceID, reason string) []string {
	if s.persistent != nil {
		return s.persistent.revokeTrustedDevice121(userID, deviceID, reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	ids := []string{}
	for id, rec := range s.sessions {
		if rec.UserID != strings.TrimSpace(userID) || rec.TrustedDeviceID != strings.TrimSpace(deviceID) || rec.Status != "active" {
			continue
		}
		rec.Status = "revoked"
		rec.RevokedAt = now
		rec.RevokedReason = firstNonEmpty(strings.TrimSpace(reason), "device-revoked")
		rec.RiskState = "compromised"
		rec.RiskReasons = mergeRiskReasons118(rec.RiskReasons, rec.RevokedReason)
		rec.RiskScore = 100
		rec.RiskAction = "revoke"
		rec.RiskEvaluatedAt = now
		rec.RiskUpdatedAt = now
		rec.DeviceTrustState = "revoked"
		s.sessions[id] = rec
		s.revokeFamilyLocked111(rec.RefreshFamily, rec.RevokedReason, now)
		ids = append(ids, id)
	}
	return ids
}

func (s *authSessionStore) applyRisk0126(sessionID, userID, state string, score int, action string, reasons []string, evaluatedAt, riskUpdatedAt time.Time) (authSessionRecord, error) {
	if s.persistent != nil {
		return s.persistent.applyRisk0126(sessionID, userID, state, score, action, reasons, evaluatedAt, riskUpdatedAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok || rec.UserID != userID || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errSessionNotFound118
	}
	rec.RiskState = normalizeRiskState118(state)
	rec.RiskScore = score
	rec.RiskAction = action
	rec.RiskReasons = mergeRiskReasons118(nil, reasons...)
	rec.RiskEvaluatedAt = evaluatedAt.UTC()
	if rec.RiskState == "normal" {
		rec.RiskUpdatedAt = time.Time{}
	} else {
		rec.RiskUpdatedAt = riskUpdatedAt.UTC()
	}
	s.sessions[sessionID] = rec
	return sanitizeSessionRecord(rec), nil
}

func (s *authSessionStore) previewRefresh0126(refreshToken string) (authSessionRecord, error) {
	if s.persistent != nil {
		return s.persistent.previewRefresh0126(refreshToken)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := hashRefreshToken(refreshToken)
	token, ok := s.tokens[hash]
	if !ok {
		return authSessionRecord{}, errRefreshTokenInvalid
	}
	if token.Status == "consumed" {
		return authSessionRecord{}, errRefreshTokenReuseDetected
	}
	if token.Status != "current" || token.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errRefreshTokenInvalid
	}
	rec, ok := s.sessions[token.SessionID]
	if !ok || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errRefreshTokenInvalid
	}
	return sanitizeSessionRecord(rec), nil
}

func sanitizeSessionRecord(record authSessionRecord) authSessionRecord {
	record.RefreshHash = ""
	if strings.TrimSpace(record.DeviceTrustState) == "" {
		record.DeviceTrustState = "unverified"
	}
	if record.BindingEpoch < 1 {
		record.BindingEpoch = 1
	}
	if strings.TrimSpace(record.RiskAction) == "" {
		switch normalizeRiskState118(record.RiskState) {
		case "compromised":
			record.RiskAction = "revoke"
			record.RiskScore = 100
		case "elevated":
			record.RiskAction = "step-up"
			if record.RiskScore < 25 {
				record.RiskScore = 25
			}
		default:
			record.RiskAction = "allow"
		}
	}
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
