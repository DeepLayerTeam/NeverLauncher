package httpapi

import (
	"errors"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// pendingProviderIdentity0296 привязывает зашифрованные учётные данные к точной
// уже аутентифицированной идентичности с учётом issuer, а не к изменяемому email
// или одному провайдеру, неоднозначному между издателями.
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

// commitPendingProviderCredential0296 вызывается только после успешного
// WebAuthn-подтверждения и выдачи сеанса Never. AAD привязывает запечатанный токен
// к конкретному владельцу, провайдеру и субъекту, исключая подмену между challenge.
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
