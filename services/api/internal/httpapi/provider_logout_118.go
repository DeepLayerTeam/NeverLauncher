package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func (s Server) authProviderLogout118(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if providerID == "" {
		writeError(w, http.StatusBadRequest, "providerId обязателен")
		return
	}
	identity, err := selectedAuthIdentity0291(s.Repo, claims.Sub, providerID, r.URL.Query().Get("issuer"))
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusConflict, "несколько issuer: укажите параметр ?issuer=<точный issuer>")
		return
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "Идентификатор поставщика не связан с текущей учётной записью")
		return
	}
	store, err := s.providerCredentialRepository116()
	if err != nil {
		writeError(w, http.StatusNotImplemented, "Репозиторий не поддерживает учётные данные провайдера")
		return
	}
	credential, err := store.GetProviderCredentialByIdentity(claims.Sub, identity.ID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusConflict, "Учётные данные поставщика отсутствуют; сеанс Never не изменён")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось прочитать учётные данные провайдера")
		return
	}
	plain, err := s.decryptProviderCredential116(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось расшифровать учётные данные провайдера")
		return
	}
	if err := s.Federation.RevokeProviderCredential(r.Context(), providerID, identity.Subject, plain); err != nil {
		if errors.Is(err, federation.ErrCapabilityUnsupported) {
			writeError(w, http.StatusNotImplemented, "Провайдер не поддерживает отзыв учётных данных на сервере; сеанс Never сохранён")
			return
		}
		writeError(w, http.StatusBadGateway, "Не удалось выполнить выход или отзыв учётных данных провайдера; сеанс Never сохранён")
		return
	}
	if err := store.DeleteProviderCredentialByIdentity(claims.Sub, identity.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "Учётные данные провайдера отозваны, но не удалось удалить их локальную запись")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-logout-" + now.Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:provider:logout", Target: providerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "provider-logged-out", "provider": providerID, "neverSessionRevoked": false, "note": "Выход из учётной записи провайдера не завершает сеанс Never"}})
}
