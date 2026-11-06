package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func recoveryKey0435(t *testing.T, id string) model.TrustedDevice {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(public)
	return model.TrustedDevice{ID: id, UserID: "recovery-0435", Name: id, Status: "active", TrustState: "verified", KeyAlgorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(public), KeyFingerprint: hex.EncodeToString(digest[:])}
}

func TestConcurrentRevokedRecoveryOnlyOneKeyWins0435(t *testing.T) {
	repo := NewMemoryRepository("https://example.test")
	ctx := context.Background()
	old := recoveryKey0435(t, "lost-0435")
	if _, err := repo.SaveTrustedDevice(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(ctx, old.UserID, old.ID, "stolen"); err != nil {
		t.Fatal(err)
	}
	next := make([]model.TrustedDevice, 16)
	for i := range next {
		next[i] = recoveryKey0435(t, fmt.Sprintf("new-0435-%d", i))
	}
	var wg sync.WaitGroup
	outcomes := make(chan error, len(next))
	for _, candidate := range next {
		wg.Add(1)
		go func(candidate model.TrustedDevice) {
			defer wg.Done()
			_, _, err := repo.RecoverRevokedTrustedDeviceKey0435(ctx, old.UserID, old.ID, candidate, time.Now().UTC())
			outcomes <- err
		}(candidate)
	}
	wg.Wait()
	close(outcomes)
	won := 0
	for err := range outcomes {
		if err == nil {
			won++
			continue
		}
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("Неожиданная ошибка восстановления: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("Параллельное восстановление завершилось успешно %d раз; ожидался один", won)
	}
	tombstone, err := repo.GetTrustedDevice(old.UserID, old.ID)
	if err != nil || tombstone.Status != "revoked" || tombstone.ReplacedByDeviceID == "" {
		t.Fatalf("Старое устройство не осталось отозванным: %+v %v", tombstone, err)
	}
	active := repo.ListTrustedDevices(old.UserID, "active")
	if len(active) != 1 || active[0].ID != tombstone.ReplacedByDeviceID {
		t.Fatalf("Неожиданные активные личности устройств: %+v", active)
	}
	if _, err := repo.SaveTrustedDevice(ctx, old); !errors.Is(err, ErrConflict) {
		t.Fatalf("Отозванный ключ восстановился: %v", err)
	}
}

func TestFailedSessionBindingCanRetryWithoutResurrectingKey0435(t *testing.T) {
	repo := NewMemoryRepository("https://example.test")
	ctx := context.Background()
	old := recoveryKey0435(t, "old-failed-0435")
	if _, err := repo.SaveTrustedDevice(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(ctx, old.UserID, old.ID, "stolen"); err != nil {
		t.Fatal(err)
	}
	failed := recoveryKey0435(t, "candidate-failed-0435")
	if _, _, err := repo.RecoverRevokedTrustedDeviceKey0435(ctx, old.UserID, old.ID, failed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeTrustedDevice(ctx, old.UserID, failed.ID, "replacement-bind-failed"); err != nil {
		t.Fatal(err)
	}
	if err := repo.ReleaseFailedRevokedDeviceRecovery0435(ctx, old.UserID, old.ID, failed.ID); err != nil {
		t.Fatal(err)
	}
	oldRow, err := repo.GetTrustedDevice(old.UserID, old.ID)
	if err != nil || oldRow.Status != "revoked" || oldRow.ReplacedByDeviceID != "" {
		t.Fatalf("Восстановлен прежний уровень доверия: %+v %v", oldRow, err)
	}
	failedRow, err := repo.GetTrustedDevice(old.UserID, failed.ID)
	if err != nil || failedRow.Status != "revoked" {
		t.Fatalf("Отклонённый кандидат не отозван: %+v %v", failedRow, err)
	}
	if _, err := repo.SaveTrustedDevice(ctx, failed); !errors.Is(err, ErrConflict) {
		t.Fatalf("Отклонённый ключ снова активен: %v", err)
	}
	retry := recoveryKey0435(t, "retry-0435")
	if _, _, err := repo.RecoverRevokedTrustedDeviceKey0435(ctx, old.UserID, old.ID, retry, time.Now().UTC()); err != nil {
		t.Fatalf("Новое восстановление после сбоя CAS отклонено: %v", err)
	}
}
