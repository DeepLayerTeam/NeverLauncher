package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestProviderCredentialEncryptionRoundTripAndAADBinding116(t *testing.T) {
	s := Server{Config: config.Config{AuthTokenSecret: "0123456789abcdef0123456789abcdef-provider-test"}}
	item := model.ProviderCredential{UserID: "user-1", IdentityID: "identity-1", Provider: "microsoft", Subject: "tenant:object"}
	ciphertext, err := s.encryptProviderCredential116(item.UserID, item.IdentityID, item.Provider, item.Subject, "microsoft-refresh-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, "microsoft-refresh-secret") || !strings.HasPrefix(ciphertext, "v1.") {
		t.Fatalf("Учётные данные провайдера не защищены надлежащим образом: %q", ciphertext)
	}
	item.EncryptedRefreshToken = ciphertext
	plain, err := s.decryptProviderCredential116(item)
	if err != nil || plain != "microsoft-refresh-secret" {
		t.Fatalf("Ошибка сохранения и чтения: исходное=%q ошибка=%v", plain, err)
	}
	item.Subject = "tenant:other-object"
	if _, err := s.decryptProviderCredential116(item); err == nil {
		t.Fatal("Ожидалось, что учётные данные с привязкой к AAD отклонят подмену субъекта")
	}
}

func TestProviderCredentialEncryptionRejectsWrongServerSecret116(t *testing.T) {
	s := Server{Config: config.Config{AuthTokenSecret: "server-secret-one-012345678901234567890"}}
	ciphertext, err := s.encryptProviderCredential116("user", "identity", "microsoft", "tenant:object", "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	other := Server{Config: config.Config{AuthTokenSecret: "server-secret-two-012345678901234567890"}}
	if _, err := other.decryptProviderCredential116(model.ProviderCredential{UserID: "user", IdentityID: "identity", Provider: "microsoft", Subject: "tenant:object", EncryptedRefreshToken: ciphertext}); err == nil {
		t.Fatal("Учётные данные, зашифрованные другим секретом установки, должны отклоняться")
	}
}
