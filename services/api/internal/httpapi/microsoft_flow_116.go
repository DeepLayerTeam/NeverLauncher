package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type microsoftLogoutRequest116 struct {
	PostLogoutRedirectURI string `json:"postLogoutRedirectUri,omitempty"`
}

func (s Server) microsoftConnector116(providerID string) (authconnector.Connector, bool) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	connector, ok := s.Federation.Connector(providerID)
	if !ok {
		return nil, false
	}
	kind, ok := connector.(interface{ ProviderKind() string })
	return connector, ok && kind.ProviderKind() == "microsoft"
}

// authMicrosoftLinkBegin116 запускает доказательство Microsoft, привязанное к уже
// аутентифицированному пользователю Never. Совпадение email никогда не доказывает владение.
func (s Server) authMicrosoftLinkBegin116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !freshNeverIdentity0268(claims, time.Now()) {
		writeError(w, http.StatusForbidden, "Требуется недавняя повторная аутентификация Never")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if err := s.Federation.EnsureLinkAllowed(providerID); err != nil {
		writeError(w, http.StatusForbidden, "Привязка к указанному провайдеру Microsoft запрещена")
		return
	}
	if _, ok := s.microsoftConnector116(providerID); !ok {
		writeError(w, http.StatusNotFound, "Провайдер Microsoft не найден")
		return
	}
	if user, err := s.Repo.GetUser(claims.Sub); err != nil || user.Status != "active" {
		writeError(w, http.StatusForbidden, "учётная запись недоступна для связывания")
		return
	}
	var req oidcBeginRequest115
	if !decodeSensitiveRequest0300(w, r, &req) {
		return
	}
	start, sealed, err := s.beginOIDC115(r, providerID, req.RedirectURI, req.DeviceID)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	tx, err := s.openOIDCTransaction115(sealed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось подготовить операцию привязки учётной записи Microsoft")
		return
	}
	tx.LinkUserID = claims.Sub
	sealed, err = s.sealOIDCTransaction115(tx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось защитить операцию привязки учётной записи Microsoft")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "provider": providerID,
		"authorizationUrl": start.AuthorizationURL, "state": start.State, "transaction": sealed, "expiresAt": start.ExpiresAt,
	}})
}

func (s Server) authMicrosoftLinkComplete116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !freshNeverIdentity0268(claims, time.Now()) {
		writeError(w, http.StatusForbidden, "Требуется недавняя повторная аутентификация Never")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if err := s.Federation.EnsureLinkAllowed(providerID); err != nil {
		writeError(w, http.StatusForbidden, "Привязка к указанному провайдеру Microsoft запрещена")
		return
	}
	if _, ok := s.microsoftConnector116(providerID); !ok {
		writeError(w, http.StatusNotFound, "Провайдер Microsoft не найден")
		return
	}
	var req oidcCompleteRequest115
	if !decodeSensitiveRequest0300(w, r, &req) {
		return
	}
	tx, err := s.openOIDCTransaction115(req.Transaction)
	if err != nil || tx.LinkUserID == "" || tx.LinkUserID != claims.Sub || tx.ProviderID != providerID || req.State == "" || req.State != tx.State || strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusUnauthorized, "Операция привязки учётной записи Microsoft недействительна или срок её действия истёк")
		return
	}
	if !s.claimBrowserTransaction0525(w, r, tx) {
		return
	}
	meta, proof, err := s.Federation.CompleteBrowserAuthProof(r.Context(), providerID, authconnector.BrowserAuthCallback{
		RedirectURI: tx.RedirectURI, Code: req.Code, State: req.State, Nonce: tx.Nonce, PKCEVerifier: tx.PKCEVerifier,
	})
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	identity, err := s.Federation.LinkAuthenticatedIdentity(claims.Sub, providerID, proof)
	if err != nil {
		if authconnector.CodeOf(err) == authconnector.ErrConflict || errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "Учётная запись Microsoft уже привязана к другому пользователю")
			return
		}
		s.writeOIDCError115(w, err)
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status != "active" {
		writeError(w, http.StatusUnauthorized, "учётная запись больше недоступна")
		return
	}
	if err := s.saveProviderCredential116(user, identity, proof.ProviderToken, false); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось безопасно сохранить учётные данные провайдера Microsoft")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-microsoft-linked-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:microsoft:linked", Target: providerID + "/" + identity.Issuer + "/" + identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "linked", "provider": meta.ID,
		"identity": map[string]any{"id": identity.ID, "provider": identity.Provider, "issuer": identity.Issuer, "subject": identity.Subject},
	}})
}

func (s Server) authProviderCredentialRefresh116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	store, err := s.providerCredentialRepository116()
	if err != nil {
		writeError(w, http.StatusNotImplemented, "Репозиторий не поддерживает учётные данные провайдера")
		return
	}
	selected, selectErr := selectedAuthIdentity0291(s.Repo, claims.Sub, providerID, r.URL.Query().Get("issuer"))
	if errors.Is(selectErr, repository.ErrConflict) {
		writeError(w, http.StatusConflict, "несколько issuer: укажите параметр ?issuer=<точный issuer>")
		return
	}
	if selectErr != nil {
		writeError(w, http.StatusNotFound, "Идентификатор провайдера отсутствует")
		return
	}
	credential, err := store.GetProviderCredentialByIdentity(claims.Sub, selected.ID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Учётные данные провайдера не найдены")
			return
		}
		writeError(w, http.StatusInternalServerError, "Не удалось прочитать учётные данные провайдера")
		return
	}
	plain, err := s.decryptProviderCredential116(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Учётные данные провайдера повреждены или не могут быть расшифрованы")
		return
	}
	refreshed, err := s.Federation.RefreshProviderCredential(r.Context(), providerID, plain, credential.Subject)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	issuer, issuerErr := model.CanonicalAuthIssuer(providerID, refreshed.Identity.Issuer)
	if issuerErr != nil || issuer != selected.Issuer || strings.TrimSpace(refreshed.Identity.Subject) != selected.Subject {
		writeError(w, http.StatusConflict, "При обновлении учётных данных провайдера изменились издатель (issuer) или субъект (subject); данные не обновлены")
		return
	}
	identity, err := s.Federation.RefreshLinkedIdentity(claims.Sub, providerID, selected.ID, refreshed)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status != "active" {
		writeError(w, http.StatusUnauthorized, "учётная запись больше недоступна")
		return
	}
	if err := s.saveProviderCredential116(user, identity, refreshed.ProviderToken, true); err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось сохранить обновлённые учётные данные провайдера")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-refreshed-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:provider-credential:refreshed", Target: providerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "refreshed", "provider": providerID,
		"identity":  map[string]any{"id": identity.ID, "provider": identity.Provider, "issuer": identity.Issuer, "subject": identity.Subject},
		"expiresAt": refreshed.ExpiresAt,
	}})
}

func (s Server) authProviderCredentialDelete116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	store, err := s.providerCredentialRepository116()
	if err != nil {
		writeError(w, http.StatusNotImplemented, "Репозиторий не поддерживает учётные данные провайдера")
		return
	}
	selected, selectErr := selectedAuthIdentity0291(s.Repo, claims.Sub, providerID, r.URL.Query().Get("issuer"))
	if errors.Is(selectErr, repository.ErrConflict) {
		writeError(w, http.StatusConflict, "несколько issuer: укажите параметр ?issuer=<точный issuer>")
		return
	}
	if selectErr != nil {
		writeError(w, http.StatusNotFound, "Идентификатор провайдера отсутствует")
		return
	}
	if err := store.DeleteProviderCredentialByIdentity(claims.Sub, selected.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "Не удалось удалить учётные данные провайдера")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "provider-credential-deleted", "provider": providerID}})
}

func (s Server) authMicrosoftLogoutURL116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	connector, ok := s.microsoftConnector116(providerID)
	if !ok {
		writeError(w, http.StatusNotFound, "Провайдер Microsoft не найден")
		return
	}
	linked := false
	for _, identity := range s.Repo.ListAuthIdentities(claims.Sub) {
		if identity.Provider == providerID {
			linked = true
			break
		}
	}
	if !linked {
		writeError(w, http.StatusForbidden, "Провайдер Microsoft не привязан к текущей учётной записи")
		return
	}
	var req microsoftLogoutRequest116
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeSensitiveRequest0300(w, r, &req) {
			return
		}
	}
	logout, ok := connector.(interface{ ProviderLogoutURL(string) (string, error) })
	if !ok {
		writeError(w, http.StatusNotImplemented, "Провайдер Microsoft не поддерживает выход через браузер")
		return
	}
	logoutURL, err := logout.ProviderLogoutURL(req.PostLogoutRedirectURI)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "provider": providerID, "logoutUrl": logoutURL,
		"note": "Выход из учётной записи провайдера и завершение сеанса Never — разные действия",
	}})
}
