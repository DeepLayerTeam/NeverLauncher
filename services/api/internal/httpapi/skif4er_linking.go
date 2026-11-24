package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func (s Server) skif4erSessionLinked102(session authSessionRecord) bool {
	if session.Provider != "skif4er-id" {
		return true
	}
	if session.IdentityID == "" {
		return false
	}
	for _, item := range s.Repo.ListAuthIdentities(session.UserID) {
		if item.ID == session.IdentityID && item.Provider == "skif4er-id" && item.UserID == session.UserID {
			return true
		}
	}
	return false
}

func (s Server) authSkif4erUnlink102(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется действительная сессия")
		return
	}
	session, ok := s.State.AuthSessions.get(claims.SessionID, claims.Sub)
	// Prove the alternative login actually works before removing the external identity.
	password := false
	for _, method := range session.AuthMethods {
		if method == "password" {
			password = true
		}
	}
	if !ok || !password || session.Provider != "local" || !freshLauncherIdentity0268(claims, time.Now()) {
		writeError(w, http.StatusForbidden, "Для отвязки войдите заново с локальным паролем Launcher")
		return
	}
	id := strings.TrimSpace(r.PathValue("identityId"))
	if id == "" || len(id) > 200 {
		writeError(w, http.StatusBadRequest, "Некорректный идентификатор")
		return
	}
	repo, ok := s.Repo.(repository.Skif4erUnlinkRepository102)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "Хранилище отвязки недоступно")
		return
	}
	if err := repo.UnlinkSkif4er102(r.Context(), claims.Sub, id); err != nil {
		switch {
		case errors.Is(err, repository.ErrNotFound):
			writeError(w, http.StatusNotFound, "Связь не найдена")
		case errors.Is(err, repository.ErrConflict):
			writeError(w, http.StatusConflict, "Необходим действующий локальный способ входа")
		default:
			writeError(w, http.StatusInternalServerError, "Не удалось удалить связь")
		}
		return
	}
	for _, item := range s.State.AuthSessions.listByUser(claims.Sub) {
		if item.Provider == "skif4er-id" && item.IdentityID == id {
			s.State.AuthSessions.revoke(item.ID, "identity-unlinked")
		}
	}
	if err := s.flushPersistenceState950("skif4er-unlink"); err != nil {
		writeError(w, http.StatusInternalServerError, "Связь удалена; не удалось сохранить состояние сессий")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-skif4er-unlinked-" + now.Format("20060102150405.000000000"), Actor: claims.Sub, Action: "auth:provider:unlinked", Target: id, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "unlinked", "identityId": id}})
}
