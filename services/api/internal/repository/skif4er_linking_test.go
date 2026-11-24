package repository

import (
	"context"
	"errors"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestSkif4erLinkLifecycle102(t *testing.T) {
	r := NewMemoryRepository("http://test.invalid")
	ctx := context.Background()
	for _, user := range []model.User{{ID: "link-owner", Email: "owner@test.invalid", PasswordHash: "test-hash", RoleID: "player"}, {ID: "link-other", Email: "other@test.invalid", PasswordHash: "test-hash", RoleID: "player"}, {ID: "link-only", Email: "only@test.invalid", RoleID: "player"}} {
		if _, err := r.SaveUser(user); err != nil {
			t.Fatal(err)
		}
	}
	input := model.AuthIdentity{UserID: "link-owner", Provider: "skif4er-id", Issuer: "https://id.skif4er.ru/realms/skif4er", Subject: "subject-one"}
	first, err := r.SaveAuthIdentity(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.SaveAuthIdentity(input)
	if err != nil || again.ID != first.ID {
		t.Fatalf("idempotency: %v %v", again, err)
	}
	other := input
	other.UserID = "link-other"
	if _, err = r.SaveAuthIdentity(other); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate owner: %v", err)
	}
	if err = r.UnlinkSkif4er102(ctx, "link-other", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-account deletion: %v", err)
	}
	if _, err = r.SaveProviderCredential(model.ProviderCredential{UserID: input.UserID, IdentityID: first.ID, Provider: input.Provider, Subject: input.Subject, EncryptedRefreshToken: "ciphertext"}); err != nil {
		t.Fatal(err)
	}
	if err = r.UnlinkSkif4er102(ctx, input.UserID, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = r.TouchAuthIdentity(first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old login resurrected: %v", err)
	}
	if _, err = r.GetProviderCredentialByIdentity(input.UserID, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("credential retained: %v", err)
	}
	next, err := r.SaveAuthIdentity(input)
	if err != nil || next.ID == first.ID {
		t.Fatalf("old binding reused: %v %v", next, err)
	}
	only := input
	only.UserID = "link-only"
	only.Subject = "only-subject"
	id, err := r.SaveAuthIdentity(only)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.UnlinkSkif4er102(ctx, only.UserID, id.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("last login removed: %v", err)
	}
}

func TestSkif4erConcurrentLink102(t *testing.T) {
	r := NewMemoryRepository("http://test.invalid")
	for _, id := range []string{"race-a", "race-b"} {
		if _, err := r.SaveUser(model.User{ID: id, Email: id + "@test.invalid", RoleID: "player"}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"race-a", "race-b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := r.SaveAuthIdentity(model.AuthIdentity{UserID: id, Provider: "skif4er-id", Issuer: "https://id.skif4er.ru/realms/skif4er", Subject: "race"})
			results <- err
		}(id)
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
}
