package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
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
	var identity model.AuthIdentity
	found := false
	for _, item := range s.Repo.ListAuthIdentities(claims.Sub) {
		if item.Provider == providerID {
			identity = item
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "provider identity не связана с текущей учётной записью")
		return
	}
	store, err := s.providerCredentialRepository116()
	if err != nil {
		writeError(w, http.StatusNotImplemented, "repository не поддерживает provider credentials")
		return
	}
	credential, err := store.GetProviderCredential(claims.Sub, providerID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusConflict, "provider credential отсутствует; Never session не изменена")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось прочитать provider credential")
		return
	}
	plain, err := s.decryptProviderCredential116(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "provider credential не может быть расшифрован")
		return
	}
	if err := s.Federation.RevokeProviderCredential(r.Context(), providerID, identity.Subject, plain); err != nil {
		if errors.Is(err, federation.ErrCapabilityUnsupported) {
			writeError(w, http.StatusNotImplemented, "provider не поддерживает server-side revoke; Never session не изменена")
			return
		}
		writeError(w, http.StatusBadGateway, "provider logout/revoke завершился ошибкой; Never session не изменена")
		return
	}
	if err := store.DeleteProviderCredential(claims.Sub, providerID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "provider credential revoked, но локальная credential запись не удалена")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-logout-" + now.Format("20060102150405.000000000"), Actor: claims.Email, Action: "auth:provider:logout", Target: providerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "provider-logged-out", "provider": providerID, "neverSessionRevoked": false, "note": "provider logout и Never session logout являются отдельными действиями"}})
}
