package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type revokeCurrentSessionsRequest struct {
	AllExceptCurrent bool `json:"allExceptCurrent"`
}

func (s Server) v1AuthSessions(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	items := s.State.AuthSessions.listByUser(claims.Sub)
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": apiContractVersion,
		"data":       map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items, "currentSessionId": claims.SessionID},
	})
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
		for _, item := range s.State.AuthSessions.listByUser(claims.Sub) {
			if item.ID != claims.SessionID && item.Status == "active" {
				s.State.AuthSessions.revoke(item.ID, "user-revoke-other-sessions")
				revoked++
			}
		}
	} else {
		revoked = s.State.AuthSessions.revokeUser(claims.Sub, "user-revoke-all-sessions")
	}
	_ = s.flushPersistenceState950("auth-v1-revoke-sessions")
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-v1-revoke-" + time.Now().UTC().Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:sessions:revoke", Target: claims.Sub, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "revokedSessions": revoked}})
}
