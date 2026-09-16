package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

// authProviderLinkBegin0120 starts an explicit browser-provider proof bound to the
// already authenticated canonical Never user. It intentionally does not inspect or
// compare e-mail addresses: possession of the provider identity is the proof.
func (s Server) authProviderLinkBegin0120(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	connector, ok := s.Federation.Connector(providerID)
	if !ok {
		writeError(w, http.StatusNotFound, "auth provider не найден")
		return
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	if !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		writeError(w, http.StatusBadRequest, "auth provider не поддерживает browser linking")
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
		writeError(w, http.StatusInternalServerError, "не удалось подготовить linking transaction")
		return
	}
	tx.LinkUserID = claims.Sub
	sealed, err = s.sealOIDCTransaction115(tx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось защитить linking transaction")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "link-proof-required",
		"provider": providerID, "authorizationUrl": start.AuthorizationURL, "state": start.State,
		"transaction": sealed, "expiresAt": start.ExpiresAt,
	}})
}

func (s Server) authProviderLinkComplete0120(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	connector, ok := s.Federation.Connector(providerID)
	if !ok {
		writeError(w, http.StatusNotFound, "auth provider не найден")
		return
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	if !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		writeError(w, http.StatusBadRequest, "auth provider не поддерживает browser linking")
		return
	}
	var req oidcCompleteRequest115
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	tx, err := s.openOIDCTransaction115(req.Transaction)
	if err != nil || tx.LinkUserID == "" || tx.LinkUserID != claims.Sub || tx.ProviderID != providerID || req.State == "" || req.State != tx.State || strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusUnauthorized, "provider linking transaction недействителен или истёк")
		return
	}
	verifiedMeta, proof, err := s.Federation.CompleteBrowserAuthProof(r.Context(), providerID, authconnector.BrowserAuthCallback{
		RedirectURI: tx.RedirectURI, Code: req.Code, State: req.State, Nonce: tx.Nonce, PKCEVerifier: tx.PKCEVerifier,
	})
	if err != nil {
		s.writeOIDCError115(w, err)
		return
	}
	identity, err := s.Federation.LinkAuthenticatedIdentity(claims.Sub, providerID, proof)
	if err != nil {
		if authconnector.CodeOf(err) == authconnector.ErrConflict || errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "provider identity уже связана с другой учётной записью")
			return
		}
		s.writeOIDCError115(w, err)
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, "учётная запись больше недоступна")
		return
	}
	if strings.TrimSpace(proof.ProviderToken) != "" {
		if err := s.saveProviderCredential116(user, identity, proof.ProviderToken, false); err != nil {
			writeError(w, http.StatusInternalServerError, "не удалось безопасно сохранить provider credential")
			return
		}
	}
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-provider-linked-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:provider:linked", Target: providerID + "/" + identity.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": "linked", "provider": verifiedMeta.ID,
		"identity": map[string]any{"id": identity.ID, "provider": identity.Provider, "subject": identity.Subject},
	}})
}

func (s Server) authFederationStatus0120(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	providers := s.Federation.Providers()
	health := s.Federation.Health(ctx)
	identities := s.Repo.ListAuthIdentities("")
	counts := make(map[string]int)
	for _, identity := range identities {
		counts[identity.Provider]++
	}
	items := make([]map[string]any, 0, len(health))
	healthy := 0
	for _, h := range health {
		if h.Healthy {
			healthy++
		}
		policy := s.Federation.ProviderPolicy(h.Metadata.ID)
		items = append(items, map[string]any{
			"id": h.Metadata.ID, "displayName": h.Metadata.DisplayName, "version": h.Metadata.Version,
			"capabilities": h.Metadata.Capabilities, "healthy": h.Healthy, "error": h.Error,
			"autoProvision": policy.AutoProvision, "defaultRole": policy.DefaultRole,
			"linkedIdentities": counts[h.Metadata.ID],
		})
	}
	ready := len(providers) > 0 && healthy == len(providers)
	status := "ready"
	if !ready {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion, "toolVersion": s.Version, "release": "auth-federation",
		"status": status, "ready": ready, "providers": items, "providerCount": len(providers),
		"healthyProviders": healthy, "identityCount": len(identities),
	}})
}
