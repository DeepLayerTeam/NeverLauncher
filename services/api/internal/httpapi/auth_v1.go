package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type revokeCurrentSessionsRequest struct {
	AllExceptCurrent bool `json:"allExceptCurrent"`
}
type renameSessionRequest118 struct {
	Device string `json:"device"`
}
type adminSessionRevokeRequest118 struct {
	UserID     string `json:"userId,omitempty"`
	ProviderID string `json:"providerId,omitempty"`
	RiskState  string `json:"riskState,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func (s Server) v1AuthSessions(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	items := s.State.AuthSessions.listByUser(claims.Sub)
	for i := range items {
		items[i].Current = items[i].ID == claims.SessionID
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items, "currentSessionId": claims.SessionID}})
}

func (s Server) v1AuthRenameSession118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req renameSessionRequest118
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	rec, err := s.State.AuthSessions.renameDevice118(strings.TrimSpace(r.PathValue("sessionId")), claims.Sub, req.Device)
	if err != nil {
		if err == errSessionName118 {
			writeError(w, http.StatusBadRequest, "device должен содержать 1-96 печатных символов")
			return
		}
		writeError(w, http.StatusNotFound, "сессия не найдена")
		return
	}
	rec.Current = rec.ID == claims.SessionID
	_ = s.flushPersistenceState950("auth-session-device-rename")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-session-rename-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:session:device-rename", Target: rec.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "renamed", "session": rec}})
}

func (s Server) v1AuthRevokeOne118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	sessionID := strings.TrimSpace(r.PathValue("sessionId"))
	rec, ok := s.State.AuthSessions.get(sessionID, claims.Sub)
	if !ok {
		writeError(w, http.StatusNotFound, "сессия не найдена")
		return
	}
	if !s.State.AuthSessions.revoke(sessionID, "user-revoke-session") {
		writeError(w, http.StatusConflict, "сессию не удалось отозвать")
		return
	}
	_ = s.flushPersistenceState950("auth-session-revoke-one")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-session-revoke-one-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:session:revoke-one", Target: rec.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "revoked", "sessionId": sessionID, "current": sessionID == claims.SessionID}})
}

func (s Server) v1AuthRevokeOthers118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	revoked := s.State.AuthSessions.revokeOthers118(claims.Sub, claims.SessionID, "user-revoke-other-sessions")
	_ = s.flushPersistenceState950("auth-session-revoke-others")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-session-revoke-others-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:sessions:revoke-others", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "revoked", "revokedSessions": revoked, "currentSessionId": claims.SessionID}})
}

func (s Server) v1AuthRevokeSessions(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req revokeCurrentSessionsRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	revoked := 0
	if req.AllExceptCurrent {
		revoked = s.State.AuthSessions.revokeOthers118(claims.Sub, claims.SessionID, "user-revoke-other-sessions")
	} else {
		revoked = s.State.AuthSessions.revokeUser(claims.Sub, "user-revoke-all-sessions")
	}
	_ = s.flushPersistenceState950("auth-v1-revoke-sessions")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-v1-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:sessions:revoke", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "revokedSessions": revoked}})
}

func (s Server) adminAuthSessions118(w http.ResponseWriter, r *http.Request) {
	items := s.State.AuthSessions.listFiltered118(strings.TrimSpace(r.URL.Query().Get("userId")), strings.TrimSpace(r.URL.Query().Get("providerId")), strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("riskState")))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items, "count": len(items)}})
}

func (s Server) adminAuthRevokeSessions118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	var req adminSessionRevokeRequest118
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.ProviderID = strings.ToLower(strings.TrimSpace(req.ProviderID))
	req.RiskState = strings.ToLower(strings.TrimSpace(req.RiskState))
	if req.UserID == "" && req.ProviderID == "" && req.RiskState == "" {
		writeError(w, http.StatusBadRequest, "нужен хотя бы один фильтр userId/providerId/riskState")
		return
	}
	if req.RiskState != "" && req.RiskState != "normal" && req.RiskState != "elevated" && req.RiskState != "compromised" {
		writeError(w, http.StatusBadRequest, "riskState должен быть normal|elevated|compromised")
		return
	}
	revoked := s.State.AuthSessions.revokeFiltered118(req.UserID, req.ProviderID, req.RiskState, firstNonEmpty(strings.TrimSpace(req.Reason), "admin-session-revoke"))
	_ = s.flushPersistenceState950("auth-admin-session-revoke")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-admin-session-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:sessions:admin-revoke", Target: firstNonEmpty(req.UserID, req.ProviderID, req.RiskState), IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "revoked", "revokedSessions": revoked}})
}

func (s Server) adminAuthRevokeProviderSessions118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if provider == "" {
		writeError(w, http.StatusBadRequest, "providerId обязателен")
		return
	}
	revoked := s.State.AuthSessions.revokeFiltered118("", provider, "", "compromised-provider:"+provider)
	_ = s.flushPersistenceState950("auth-admin-provider-session-revoke")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-compromise-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:provider:sessions:revoke-compromised", Target: provider, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "revoked", "providerId": provider, "revokedSessions": revoked}})
}
