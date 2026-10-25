package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func TestPendingProviderCredential0296SealedUntilPasskeyProof(t *testing.T) {
	repo := repository.NewMemoryRepository("https://launcher.example.test")
	identity, err := repo.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "parity-browser", Issuer: "https://idp.example.test", Subject: "subject-browser"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := repo.GetUser("admin")
	if err != nil {
		t.Fatal(err)
	}
	api := Server{Config: config.Config{AuthTokenSecret: "0123456789abcdef0123456789abcdef-parity"}, Repo: repo, State: NewRuntimeState(), Federation: federation.New(repo)}
	if err := api.State.Passkeys.saveCredential(passkeyCredential117{ID: "active-passkey", UserID: user.ID, CredentialID: []byte("id-for-mfa"), Status: "active"}); err != nil {
		t.Fatal(err)
	}
	continuation, err := api.startPasskeyMFAContinuation117(user, identity.Provider, identity.ID, "desktop", []string{"oidc"}, "secret-browser-refresh")
	if err != nil {
		t.Fatal(err)
	}
	token, ok := continuation["transactionToken"].(string)
	if !ok || token == "" {
		t.Fatal("missing passkey continuation")
	}
	challenge, err := api.State.Passkeys.consumeChallenge(token, "passkey-mfa-login")
	if err != nil {
		t.Fatal(err)
	}
	sealed := metadataString117(challenge.Metadata, "sealedProviderCredential")
	if sealed == "" || strings.Contains(sealed, "secret-browser-refresh") {
		t.Fatal("provider credential was not sealed in short-lived challenge")
	}
	if _, err := repo.GetProviderCredentialByIdentity(user.ID, identity.ID); err == nil {
		t.Fatal("provider credential stored before Never WebAuthn proof")
	}
	if err := api.commitPendingProviderCredential0296(user, identity.Provider, identity.ID, sealed+"tampered"); err == nil {
		t.Fatal("tampered AEAD token accepted")
	}
	if err := api.commitPendingProviderCredential0296(user, identity.Provider, "different-identity", sealed); err == nil {
		t.Fatal("wrong identity accepted")
	}
	if err := api.commitPendingProviderCredential0296(user, identity.Provider, identity.ID, sealed); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetProviderCredentialByIdentity(user.ID, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := api.decryptProviderCredential116(stored)
	if err != nil || decrypted != "secret-browser-refresh" {
		t.Fatalf("credential not safely persisted after verification: %v", err)
	}
}
