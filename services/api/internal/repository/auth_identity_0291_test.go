package repository

import (
	"context"
	"errors"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestIssuerScopedIdentityMemory0291(t *testing.T) {
	r := NewMemoryRepository("http://test.invalid")
	alice, err := r.SaveUser(model.User{ID: "issuer-alice", Email: "alice@test.invalid", RoleID: "player", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := r.SaveUser(model.User{ID: "issuer-bob", Email: "bob@test.invalid", RoleID: "player", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	one, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: alice.ID, Provider: "oidc", Issuer: "https://one.example", Subject: "same", Email: "shared@test.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: bob.ID, Provider: "oidc", Issuer: "https://two.example", Subject: "same", Email: "shared@test.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if one.ID == two.ID || one.UserID == two.UserID {
		t.Fatal("issuer identities collapsed")
	}
	if _, err := r.GetAuthIdentity("oidc", "same"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unscoped lookup must fail closed: %v", err)
	}
	scoped, err := r.GetAuthIdentityByIssuer("oidc", "https://two.example", "same")
	if err != nil || scoped.UserID != bob.ID {
		t.Fatalf("issuer lookup failed: %+v / %v", scoped, err)
	}
	if _, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: bob.ID, Provider: "oidc", Issuer: "https://one.example", Subject: "same"}); err == nil {
		t.Fatal("reassignment accepted")
	}
	if _, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: bob.ID, Provider: "oidc", Issuer: "https://two.example", Subject: "another"}); err == nil {
		t.Fatal("issuer subject rewrite accepted")
	}
	// JIT is idempotent and scoped too.
	u, identity, err := r.SaveFederatedUser(context.Background(), model.User{ID: "other", Email: "other@identity.invalid", RoleID: "player"}, model.AuthIdentity{Provider: "oidc", Issuer: "https://third.example", Subject: "same"})
	if err != nil || identity.UserID != u.ID {
		t.Fatalf("JIT failed %+v / %v", identity, err)
	}
}

func TestCredentialCannotCrossIssuerMemory0291(t *testing.T) {
	r := NewMemoryRepository("http://test.invalid")
	first, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "oidc", Issuer: "https://one.example", Subject: "same"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: "admin", Provider: "oidc", Issuer: "https://two.example", Subject: "same"})
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []model.AuthIdentity{first, second} {
		_, err := r.SaveProviderCredential(model.ProviderCredential{UserID: "admin", IdentityID: identity.ID, Provider: "oidc", Subject: "same", EncryptedRefreshToken: "ciphertext"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.GetProviderCredential("admin", "oidc"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ambiguous token lookup: %v", err)
	}
	if _, err := r.GetProviderCredentialByIdentity("admin", second.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteProviderCredential("admin", "oidc"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ambiguous revoke accepted: %v", err)
	}
	if err := r.DeleteProviderCredentialByIdentity("admin", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetProviderCredentialByIdentity("admin", second.ID); err != nil {
		t.Fatal("other issuer token lost", err)
	}
}

func TestMinecraftUUIDImmutableMemory0291(t *testing.T) {
	r := NewMemoryRepository("http://test.invalid")
	const uuid = "11111111-2222-4333-8444-555555555555"
	profile, err := r.SaveMinecraftProfile(model.MinecraftProfile{UserID: "admin", UUID: uuid, Name: "Example", Issuer: "neverlauncher", Realm: "local", Subject: uuid})
	if err != nil {
		t.Fatal(err)
	}
	changed := profile
	changed.UUID = "99999999-2222-4333-8444-555555555555"
	if _, err := r.SaveMinecraftProfile(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("UUID replacement accepted: %v", err)
	}
	changed = profile
	changed.Issuer = "external"
	if _, err := r.SaveMinecraftProfile(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("unverified issuer rewrite accepted: %v", err)
	}
	saved, err := r.GetMinecraftProfileByUser("admin")
	if err != nil || saved.UUID != uuid {
		t.Fatalf("game UUID changed: %+v, %v", saved, err)
	}
}
