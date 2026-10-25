package httpapi

import (
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// pendingProviderIdentity0296 pins the encrypted credential to the exact
// already-authenticated issuer-scoped identity rather than a mutable email or
// provider-only selection (which can be ambiguous across issuers).
func (s Server) pendingProviderIdentity0296(userID, provider, identityID string) (model.AuthIdentity, error) {
	if userID == "" || identityID == "" || strings.TrimSpace(provider) == "" {
		return model.AuthIdentity{}, errors.New("pending provider identity is incomplete")
	}
	for _, identity := range s.Repo.ListAuthIdentities(userID) {
		if identity.ID == identityID && identity.UserID == userID && identity.Provider == provider && identity.Subject != "" {
			return identity, nil
		}
	}
	return model.AuthIdentity{}, errors.New("pending provider identity changed or unlinked")
}

// commitPendingProviderCredential0296 is invoked only after a successful
// WebAuthn assertion and Never session issuance. AAD binds the sealed token to
// the exact owner/provider/subject so it cannot be swapped between challenges.
func (s Server) commitPendingProviderCredential0296(user model.User, provider, identityID, sealed string) error {
	identity, err := s.pendingProviderIdentity0296(user.ID, provider, identityID)
	if err != nil {
		return err
	}
	credential := model.ProviderCredential{UserID: user.ID, IdentityID: identity.ID, Provider: identity.Provider, Subject: identity.Subject, EncryptedRefreshToken: sealed}
	plaintext, err := s.decryptProviderCredential116(credential)
	if err != nil {
		return err
	}
	return s.saveProviderCredential116(user, identity, plaintext, false)
}
