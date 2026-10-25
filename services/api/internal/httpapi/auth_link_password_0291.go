package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type passwordIdentityProof0291 struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// Self-service legacy issuer migration for SQL/HTTP/local password providers:
// a valid Never session and a fresh successful password verification from the
// explicitly selected external provider are both required. No JIT provisioning,
// cross-provider failover, email-based matching or password export occurs.
func (s Server) authProviderLinkPassword0291(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status != "active" {
		writeError(w, http.StatusForbidden, "учётная запись недоступна")
		return
	}
	providerID := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req passwordIdentityProof0291
	if err := decoder.Decode(&req); err != nil || len(req.Identifier) > 512 || len(req.Password) > 4096 || strings.TrimSpace(req.Identifier) == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "некорректное доказательство учётной записи")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "ожидался один JSON объект")
		return
	}
	// Each external credential proof is rate-limited independently from the
	// canonical user session to prevent a signed-in attacker from guessing
	// passwords of other accounts or exhausting the provider.
	rateKey := "provider-link:" + providerID + ":" + strings.ToLower(strings.TrimSpace(req.Identifier))
	if allowed, retry := s.State.Security.allowLogin(rateKey, clientIP(r)); !allowed {
		writeError(w, http.StatusTooManyRequests, "слишком много неудачных попыток; повторите после "+retry.Format(time.RFC3339))
		return
	}
	linked, proof, err := s.Federation.LinkPasswordIdentity(r.Context(), user.ID, providerID, authconnector.PasswordRequest{Identifier: req.Identifier, Secret: req.Password})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) || authconnector.CodeOf(err) == authconnector.ErrConflict {
			writeError(w, http.StatusConflict, "external identity уже связана с другим пользователем")
			return
		}
		if errors.Is(err, federation.ErrCapabilityUnsupported) || errors.Is(err, federation.ErrProviderNotFound) {
			writeError(w, http.StatusBadRequest, "provider не поддерживает выбранный способ подтверждения")
			return
		}
		if authconnector.CodeOf(err) == authconnector.ErrInvalidCredentials {
			s.State.Security.recordLoginFailure(rateKey, clientIP(r))
			_ = s.flushPersistenceState950("auth-password-link-failed")
			writeError(w, http.StatusUnauthorized, "неверные credentials провайдера")
			return
		}
		writeError(w, http.StatusBadGateway, "не удалось подтвердить внешнюю учётную запись")
		return
	}
	if proof.ProviderToken != "" {
		if err := s.saveProviderCredential116(user, linked, proof.ProviderToken, false); err != nil {
			writeError(w, http.StatusInternalServerError, "credential нельзя сохранить безопасно")
			return
		}
	}
	s.State.Security.recordLoginSuccess(rateKey, clientIP(r))
	_ = s.flushPersistenceState950("auth-password-link-success")
	now := time.Now().UTC()
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "auth-password-link-" + now.Format("20060102150405.000000000"), Actor: user.Email, Action: "auth:provider:linked-password", Target: providerID + "/" + linked.Issuer + "/" + linked.Subject, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: now})
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "linked", "identity": map[string]any{"id": linked.ID, "provider": linked.Provider, "issuer": linked.Issuer, "subject": linked.Subject}}})
}
