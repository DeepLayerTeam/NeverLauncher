package httpapi

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	errSessionNotFound118 = errors.New("session not found")
	errSessionName118     = errors.New("invalid session device name")
)

func normalizeRiskState118(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "elevated":
		return "elevated"
	case "compromised":
		return "compromised"
	default:
		return "normal"
	}
}

func mergeRiskReasons118(existing []string, extra ...string) []string {
	seen := map[string]struct{}{}
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
	sort.Strings(out)
	return out
}

func applySessionObservation118(rec *authSessionRecord, ip, userAgent string, now time.Time) {
	if rec == nil {
		return
	}
	ip = strings.TrimSpace(ip)
	userAgent = strings.TrimSpace(userAgent)
	if rec.RiskState == "" {
		rec.RiskState = "normal"
	}
	if rec.RiskReasons == nil {
		rec.RiskReasons = []string{}
	}
	if rec.LastIP == "" {
		rec.LastIP = firstNonEmpty(rec.IP, ip)
	}
	if rec.LastUserAgent == "" {
		rec.LastUserAgent = firstNonEmpty(rec.UserAgent, userAgent)
	}
	changed := false
	if ip != "" && rec.LastIP != "" && ip != rec.LastIP {
		rec.RiskReasons = mergeRiskReasons118(rec.RiskReasons, "ip-changed")
		changed = true
	}
	if userAgent != "" && rec.LastUserAgent != "" && userAgent != rec.LastUserAgent {
		rec.RiskReasons = mergeRiskReasons118(rec.RiskReasons, "user-agent-changed")
		changed = true
	}
	if changed && rec.RiskState != "compromised" {
		rec.RiskState = "elevated"
		rec.RiskUpdatedAt = now.UTC()
	}
	if ip != "" {
		rec.LastIP = ip
	}
	if userAgent != "" {
		rec.LastUserAgent = userAgent
	}
}

func normalizeDeviceName118(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 1 || len(v) > 96 {
		return "", errSessionName118
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", errSessionName118
		}
	}
	return v, nil
}

func (s *authSessionStore) renameDevice118(sessionID, userID, name string) (authSessionRecord, error) {
	name, err := normalizeDeviceName118(name)
	if err != nil {
		return authSessionRecord{}, err
	}
	if s.persistent != nil {
		return s.persistent.renameDevice118(sessionID, userID, name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[sessionID]
	if !ok || rec.UserID != userID || rec.Status != "active" || rec.ExpiresAt.Before(time.Now().UTC()) {
		return authSessionRecord{}, errSessionNotFound118
	}
	rec.Device = name
	rec.DeviceRenamedAt = time.Now().UTC()
	s.sessions[sessionID] = rec
	return sanitizeSessionRecord(rec), nil
}

func (s *authSessionStore) revokeOthers118(userID, currentSessionID, reason string) int {
	if s.persistent != nil {
		return s.persistent.revokeOthers118(userID, currentSessionID, reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for id, rec := range s.sessions {
		if rec.UserID != userID || rec.ID == currentSessionID || rec.Status != "active" {
			continue
		}
		rec.Status = "revoked"
		rec.RevokedAt = now
		rec.RevokedReason = firstNonEmpty(reason, "user-revoke-other-sessions")
		s.sessions[id] = rec
		s.revokeFamilyLocked111(rec.RefreshFamily, rec.RevokedReason, now)
		count++
	}
	return count
}

func (s *authSessionStore) listFiltered118(userID, provider, status, risk string) []authSessionRecord {
	if s.persistent != nil {
		return s.persistent.listFiltered118(userID, provider, status, risk)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	provider = strings.ToLower(strings.TrimSpace(provider))
	status = strings.ToLower(strings.TrimSpace(status))
	risk = strings.ToLower(strings.TrimSpace(risk))
	out := []authSessionRecord{}
	for _, rec := range s.sessions {
		if userID != "" && rec.UserID != userID {
			continue
		}
		if provider != "" && strings.ToLower(rec.Provider) != provider {
			continue
		}
		if status != "" && strings.ToLower(rec.Status) != status {
			continue
		}
		if risk != "" && normalizeRiskState118(rec.RiskState) != risk {
			continue
		}
		out = append(out, sanitizeSessionRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out
}

func (s *authSessionStore) revokeFiltered118(userID, provider, risk, reason string) int {
	if s.persistent != nil {
		return s.persistent.revokeFiltered118(userID, provider, risk, reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	provider = strings.ToLower(strings.TrimSpace(provider))
	risk = strings.ToLower(strings.TrimSpace(risk))
	now := time.Now().UTC()
	count := 0
	for id, rec := range s.sessions {
		if rec.Status != "active" {
			continue
		}
		if userID != "" && rec.UserID != userID {
			continue
		}
		if provider != "" && strings.ToLower(rec.Provider) != provider {
			continue
		}
		if risk != "" && normalizeRiskState118(rec.RiskState) != risk {
			continue
		}
		rec.Status = "revoked"
		rec.RevokedAt = now
		rec.RevokedReason = firstNonEmpty(reason, "admin-session-revoke")
		if risk == "compromised" || strings.Contains(rec.RevokedReason, "compromised") {
			rec.RiskState = "compromised"
			rec.RiskReasons = mergeRiskReasons118(rec.RiskReasons, rec.RevokedReason)
			rec.RiskUpdatedAt = now
		}
		s.sessions[id] = rec
		s.revokeFamilyLocked111(rec.RefreshFamily, rec.RevokedReason, now)
		count++
	}
	return count
}

func sessionRequestMetadata118(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	return clientIP(r), r.UserAgent()
}
