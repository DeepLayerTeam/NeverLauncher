package httpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const providerCredentialCipherVersion116 = "v1"

func (s Server) providerCredentialRepository116() (repository.ProviderCredentialRepository, error) {
	store, ok := s.Repo.(repository.ProviderCredentialRepository)
	if !ok {
		return nil, errors.New("repository does not support provider credentials")
	}
	return store, nil
}

func (s Server) providerCredentialAEAD116() (cipher.AEAD, error) {
	secret := strings.TrimSpace(s.Config.AuthTokenSecret)
	if secret == "" {
		return nil, errors.New("auth token secret is empty")
	}
	key := sha256.Sum256([]byte("NeverLauncher/provider-credential/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func providerCredentialAAD116(userID, identityID, provider, subject string) []byte {
	return []byte("NeverLauncher/provider-credential/v1\x00" + strings.TrimSpace(userID) + "\x00" + strings.TrimSpace(identityID) + "\x00" + strings.ToLower(strings.TrimSpace(provider)) + "\x00" + strings.TrimSpace(subject))
}

func (s Server) encryptProviderCredential116(userID, identityID, provider, subject, token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 32768 {
		return "", errors.New("provider refresh token is empty or too large")
	}
	aead, err := s.providerCredentialAEAD116()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, []byte(token), providerCredentialAAD116(userID, identityID, provider, subject))
	payload := append(nonce, sealed...)
	return providerCredentialCipherVersion116 + "." + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s Server) decryptProviderCredential116(item model.ProviderCredential) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(item.EncryptedRefreshToken), ".", 2)
	if len(parts) != 2 || parts[0] != providerCredentialCipherVersion116 {
		return "", errors.New("unsupported provider credential ciphertext version")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	aead, err := s.providerCredentialAEAD116()
	if err != nil {
		return "", err
	}
	if len(raw) <= aead.NonceSize() {
		return "", errors.New("provider credential ciphertext is truncated")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], providerCredentialAAD116(item.UserID, item.IdentityID, item.Provider, item.Subject))
	if err != nil {
		return "", err
	}
	if len(plain) == 0 || len(plain) > 32768 {
		return "", errors.New("provider credential plaintext is invalid")
	}
	return string(plain), nil
}

func (s Server) saveProviderCredential116(user model.User, identity model.AuthIdentity, providerToken string, refreshed bool) error {
	providerToken = strings.TrimSpace(providerToken)
	if providerToken == "" {
		return nil
	}
	store, err := s.providerCredentialRepository116()
	if err != nil {
		return err
	}
	if user.ID == "" || identity.ID == "" || identity.UserID != user.ID || identity.Provider == "" || identity.Subject == "" {
		return errors.New("provider credential identity boundary is incomplete")
	}
	encrypted, err := s.encryptProviderCredential116(user.ID, identity.ID, identity.Provider, identity.Subject, providerToken)
	if err != nil {
		return err
	}
	item := model.ProviderCredential{
		UserID: user.ID, IdentityID: identity.ID, Provider: identity.Provider, Subject: identity.Subject,
		EncryptedRefreshToken: encrypted,
	}
	if refreshed {
		item.LastRefreshedAt = time.Now().UTC()
	}
	if _, err := store.SaveProviderCredential(item); err != nil {
		return fmt.Errorf("save provider credential: %w", err)
	}
	return nil
}
