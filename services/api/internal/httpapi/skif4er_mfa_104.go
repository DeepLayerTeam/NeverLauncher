package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const oidcMFAPurpose104 = "skif4er-oidc-totp-login"

// Read errors must not be interpreted as MFA being disabled.
func (s Server) loginMFAPolicy104(userID string) (string, bool, error) {
	var policy string
	if p := s.State.Passkeys.persistent; p != nil {
		var err error
		policy, err = p.policyChecked104(userID)
		if err != nil {
			return "", false, err
		}
	} else {
		policy = s.State.Passkeys.policy(userID)
	}
	if policy == "" {
		return "", false, errors.New("invalid MFA policy")
	}
	if p := s.State.Security.persistent; p != nil {
		enabled, err := p.totpEnabledChecked104(userID)
		if err != nil {
			return "", false, err
		}
		return policy, enabled, nil
	}
	return policy, s.State.Security.totpEnabled(userID), nil
}

func (s Server) skif4erSessionMFA104(session authSessionRecord) bool {
	if session.Provider != "skif4er-id" {
		return true
	}
	policy, enabled, err := s.loginMFAPolicy104(session.UserID)
	if err != nil {
		return false
	}
	strength := authMethodStrength117(session.AuthMethods)
	allowed := true
	if policy == mfaPhishingResistant117 {
		allowed = strength == "phishing-resistant"
	} else if enabled || policy == mfaRequired117 {
		allowed = authStrengthLevel117(strength) >= authStrengthLevel117("mfa")
	}
	if !allowed && session.ID != "" {
		s.State.AuthSessions.revoke(session.ID, "mfa-policy-changed")
	}
	return allowed
}

// Store a keyed digest rather than a recoverable six-digit code. The lifetime
// covers every accepted adjacent TOTP time window, including clock skew.
func (s Server) claimTOTP104(r *http.Request, userID, code string) error {
	store, ok := s.Repo.(browserNonceStore0525)
	if !ok || strings.TrimSpace(s.Config.AuthTokenSecret) == "" || len(strings.TrimSpace(code)) != 6 {
		return errors.New("TOTP replay store unavailable")
	}
	mac := hmac.New(sha256.New, []byte(s.Config.AuthTokenSecret))
	mac.Write([]byte("NeverLauncher/TOTP/104\x00" + userID + "\x00" + strings.TrimSpace(code)))
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	return store.ConsumeDurableNonce(ctx, "skif4er-totp-104", hex.EncodeToString(mac.Sum(nil)), userID, nil, time.Now().UTC().Add(2*time.Minute))
}

func (s Server) startOIDCMFA104(w http.ResponseWriter, r *http.Request, result federation.Result, deviceID string) {
	challenge, err := newChallengeBytes117()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось создать MFA challenge")
		return
	}
	meta := map[string]any{"provider": result.Provider.ID, "identityId": result.Identity.ID, "deviceId": deviceID, "authMethods": result.AuthMethods}
	if result.ProviderToken != "" {
		identity, err := s.pendingProviderIdentity0296(result.User.ID, result.Provider.ID, result.Identity.ID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Идентичность изменилась")
			return
		}
		sealed, err := s.encryptProviderCredential116(result.User.ID, identity.ID, identity.Provider, identity.Subject, result.ProviderToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Не удалось защитить данные провайдера")
			return
		}
		meta["sealedProviderCredential"] = sealed
	}
	token, err := s.State.Passkeys.createChallenge(result.User.ID, oidcMFAPurpose104, challenge, meta)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище MFA недоступно")
		return
	}
	s.audit(r, result.User.ID, "auth:oidc:mfa-required", result.Provider.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "mfa-required", "method": "totp-or-recovery", "transactionToken": token, "expiresInSeconds": int(webauthnChallengeTTL117.Seconds())}})
}

type oidcMFARequest104 struct {
	TransactionToken string `json:"transactionToken"`
	TOTP             string `json:"totp,omitempty"`
	RecoveryCode     string `json:"recoveryCode,omitempty"`
}

func (s Server) authOIDCMFAComplete104(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req oidcMFARequest104
	if !decodeSensitiveRequest0300(w, r, &req) {
		return
	}
	req.TOTP, req.RecoveryCode = strings.TrimSpace(req.TOTP), strings.TrimSpace(req.RecoveryCode)
	if r.PathValue("providerId") != "skif4er-id" || req.TransactionToken == "" || (req.TOTP == "") == (req.RecoveryCode == "") {
		writeError(w, http.StatusBadRequest, "Требуется один метод MFA")
		return
	}
	rateKey := "oidc:skif4er-id:" + clientIP(r)
	if allowed, _ := s.State.Security.allowLogin(rateKey, clientIP(r)); !allowed {
		writeError(w, http.StatusTooManyRequests, "Слишком много попыток входа")
		return
	}
	tx, err := s.State.Passkeys.consumeChallenge(req.TransactionToken, oidcMFAPurpose104)
	if err != nil {
		s.State.Security.recordLoginFailure(rateKey, clientIP(r))
		s.audit(r, "unknown", "auth:oidc:mfa-rejected", "invalid-or-used-challenge")
		writeError(w, http.StatusUnauthorized, "MFA challenge недействителен или уже использован")
		return
	}
	provider := metadataString117(tx.Metadata, "provider")
	identityID := metadataString117(tx.Metadata, "identityId")
	user, err := s.Repo.GetUser(tx.UserID)
	identity, identityErr := s.pendingProviderIdentity0296(tx.UserID, provider, identityID)
	connector, found := s.Federation.Connector(provider)
	policy, enabled, policyErr := s.loginMFAPolicy104(tx.UserID)
	if err != nil || user.Status != "active" || identityErr != nil || !found || provider != "skif4er-id" || policyErr != nil || !enabled || policy == mfaPhishingResistant117 {
		s.audit(r, tx.UserID, "auth:oidc:mfa-rejected", "identity-or-policy-changed")
		writeError(w, http.StatusUnauthorized, "Идентичность или политика MFA изменилась; войдите заново")
		return
	}
	var upstream string
	if sealed := metadataString117(tx.Metadata, "sealedProviderCredential"); sealed != "" {
		upstream, err = s.decryptProviderCredential116(model.ProviderCredential{UserID: user.ID, IdentityID: identity.ID, Provider: provider, Subject: identity.Subject, EncryptedRefreshToken: sealed})
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Данные провайдера недействительны")
			return
		}
	}
	s.finishFederatedLogin115(w, r, federation.Result{User: user, Identity: identity, Provider: connector.Metadata(), AuthMethods: metadataStrings117(tx.Metadata, "authMethods"), ProviderToken: upstream}, metadataString117(tx.Metadata, "deviceId"), req.TOTP, req.RecoveryCode, rateKey)
}
