package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
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

// authMicrosoftLinkBegin116 starts a Microsoft proof bound to the already
// authenticated Never user. Email equality is never considered proof of ownership.
func (s Server) authMicrosoftLinkBegin116(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if _, ok := s.microsoftConnector116(providerID); !ok {
		writeError(w, http.StatusNotFound, "Microsoft provider не найден")
		return
	}
	var req oidcBeginRequest115
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	start, sealed, err := s.beginOIDC115(r, providerID, req.RedirectURI, req.DeviceID)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	tx, err := s.openOIDCTransaction115(sealed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось подготовить Microsoft linking transaction")
		return
	}
	tx.LinkUserID = claims.Sub
	sealed, err = s.sealOIDCTransaction115(tx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось защитить Microsoft linking transaction")
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
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	if _, ok := s.microsoftConnector116(providerID); !ok {
		writeError(w, http.StatusNotFound, "Microsoft provider не найден")
		return
	}
	var req oidcCompleteRequest115
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	tx, err := s.openOIDCTransaction115(req.Transaction)
	if err != nil || tx.LinkUserID == "" || tx.LinkUserID != claims.Sub || tx.ProviderID != providerID || req.State == "" || req.State != tx.State || strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusUnauthorized, "Microsoft linking transaction недействителен или истёк")
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
			writeError(w, http.StatusConflict, "Microsoft identity уже связана с другой учётной записью")
			return
		}
		s.writeOIDCError115(w, err)
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "учётная запись больше недоступна")
		return
	}
	if err := s.saveProviderCredential116(user, identity, proof.ProviderToken, false); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось безопасно сохранить Microsoft provider credential")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-microsoft-linked-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:microsoft:linked", Target: providerID + "/" + identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "linked", "provider": meta.ID,
		"identity": map[string]any{"id": identity.ID, "provider": identity.Provider, "subject": identity.Subject},
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
		writeError(w, http.StatusNotImplemented, "repository не поддерживает provider credentials")
		return
	}
	credential, err := store.GetProviderCredential(claims.Sub, providerID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "provider credential не найден")
			return
		}
		writeError(w, http.StatusInternalServerError, "не удалось прочитать provider credential")
		return
	}
	plain, err := s.decryptProviderCredential116(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "provider credential повреждён или не может быть расшифрован")
		return
	}
	refreshed, err := s.Federation.RefreshProviderCredential(r.Context(), providerID, plain, credential.Subject)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	identity, err := s.Federation.LinkAuthenticatedIdentity(claims.Sub, providerID, refreshed)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "учётная запись больше недоступна")
		return
	}
	if err := s.saveProviderCredential116(user, identity, refreshed.ProviderToken, true); err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить rotated provider credential")
		return
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-refreshed-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:provider-credential:refreshed", Target: providerID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "refreshed", "provider": providerID,
		"identity":  map[string]any{"id": identity.ID, "provider": identity.Provider, "subject": identity.Subject},
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
		writeError(w, http.StatusNotImplemented, "repository не поддерживает provider credentials")
		return
	}
	if err := store.DeleteProviderCredential(claims.Sub, providerID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "не удалось удалить provider credential")
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
		writeError(w, http.StatusNotFound, "Microsoft provider не найден")
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
		writeError(w, http.StatusForbidden, "Microsoft provider не связан с текущей учётной записью")
		return
	}
	var req microsoftLogoutRequest116
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
			return
		}
	}
	logout, ok := connector.(interface{ ProviderLogoutURL(string) (string, error) })
	if !ok {
		writeError(w, http.StatusNotImplemented, "Microsoft provider не поддерживает front-channel logout")
		return
	}
	logoutURL, err := logout.ProviderLogoutURL(req.PostLogoutRedirectURI)
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "provider": providerID, "logoutUrl": logoutURL,
		"note": "provider logout отделён от Never session logout",
	}})
}
