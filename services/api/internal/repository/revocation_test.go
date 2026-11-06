package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Устаревший писатель с исходным законно зарегистрированным ключом не может
// отменить явный отзыв. Попытка заменить ключ на месте также отклоняется.
func TestRevokedDeviceKeyCannotBeResurrected0434(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("https://api.example.test")
	enrolled := model.TrustedDevice{
		ID: "dev-0434", UserID: "user-0434", Name: "workstation", Status: "active", TrustState: "verified",
		PublicKey: "original-public-key", KeyFingerprint: "original-fingerprint", KeyAlgorithm: "ed25519",
	}
	if _, err := repo.SaveTrustedDevice(ctx, enrolled); err != nil {
		t.Fatal(err)
	}
	swapped := enrolled
	swapped.PublicKey = "replacement-without-rotation"
	swapped.KeyFingerprint = "replacement-fingerprint"
	if _, err := repo.SaveTrustedDevice(ctx, swapped); !errors.Is(err, ErrConflict) {
		t.Fatalf("Незаметная замена ключа: %v", err)
	}
	revoked, err := repo.RevokeTrustedDevice(ctx, enrolled.UserID, enrolled.ID, "device-compromised")
	if err != nil || revoked.Device.Status != "revoked" {
		t.Fatalf("Отзыв: %+v %v", revoked, err)
	}
	if _, err := repo.SaveTrustedDevice(ctx, enrolled); !errors.Is(err, ErrConflict) {
		t.Fatalf("Устаревший процесс записи устройства восстановил отозванный ключ: %v", err)
	}
	alias := enrolled
	alias.ID = "dev-alias-0434"
	if _, err := repo.SaveTrustedDevice(ctx, alias); !errors.Is(err, ErrConflict) {
		t.Fatalf("Отозванный ключ повторно зарегистрирован под другим ID: %v", err)
	}
	after, err := repo.GetTrustedDevice(enrolled.UserID, enrolled.ID)
	if err != nil || after.Status != "revoked" || after.KeyFingerprint != enrolled.KeyFingerprint {
		t.Fatalf("Данные об отзыве неожиданно изменились: %+v %v", after, err)
	}
	if second, err := repo.RevokeTrustedDevice(ctx, enrolled.UserID, enrolled.ID, "retry"); err != nil || !second.AlreadyRevoked {
		t.Fatalf("Нарушена идемпотентность: %+v %v", second, err)
	}
}

func TestRevokedMinecraftTokenCannotBeResurrected0434(t *testing.T) {
	repo := NewMemoryRepository("https://api.example.test")
	session := model.MinecraftSession{
		ID: "mc-0434", UserID: "user-0434", NeverSessionID: "sess-0434", ProfileUUID: "00000000-0000-4000-8000-000000000434",
		AccessTokenHash: "hash-0434", Status: "active", ExpiresAt: time.Now().Add(time.Hour),
		TrustedDeviceID: "dev-0434", BindingEpoch: 2,
	}
	if _, err := repo.SaveMinecraftSession(session); err != nil {
		t.Fatal(err)
	}
	changed := session
	changed.BindingEpoch = 3
	if _, err := repo.SaveMinecraftSession(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("Учётные данные повторно привязаны без выдачи: %v", err)
	}
	if err := repo.RevokeMinecraftSession(session.ID, "parent-session-revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveMinecraftSession(session); !errors.Is(err, ErrConflict) {
		t.Fatalf("Отозванные игровые учётные данные восстановлены: %v", err)
	}
	existing, err := repo.GetMinecraftSessionByTokenHash(session.AccessTokenHash)
	if err != nil || existing.Status != "revoked" {
		t.Fatalf("Игровые учётные данные потеряли отметку об удалении: %+v %v", existing, err)
	}
}
