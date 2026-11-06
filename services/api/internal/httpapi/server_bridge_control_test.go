package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestServerBridgeControlValidation0195(t *testing.T) {
	if _, err := validateServerBridgeControlRequest0195("player.kick", map[string]string{"username": "Steve", "reason": "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateServerBridgeControlRequest0195("server.console", map[string]string{"command": "/save-all flush"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/", "stop", "op Steve", "say ok\nstop"} {
		if _, err := validateServerBridgeControlRequest0195("server.console", map[string]string{"command": bad}); err == nil {
			t.Fatalf("unsafe/non-allowlisted console command accepted: %q", bad)
		}
	}
	if _, err := validateServerBridgeControlRequest0195("server.shell", map[string]string{"command": "id"}); err == nil {
		t.Fatal("shell control type must not exist")
	}
}

// Отключения с привязкой к сеансу доставляются транзакцией отзыва Backend. Они
// должны отличаться от модераторских отключений только по имени и не могут
// принимать недоверенный или неоднозначный корреляционный ID.
func TestSessionBoundKickPayload0418(t *testing.T) {
	correlation := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	payload, err := validateServerBridgeControlRequest0195("player.kick", map[string]string{
		"username": "Steve", "reason": "Launcher session invalidated", "sessionCorrelationId": correlation,
	})
	if err != nil || payload["sessionCorrelationId"] != correlation {
		t.Fatalf("valid session-specific kick was rejected: %v", err)
	}
	for _, bad := range []string{"short", "", "A" + correlation[1:], "g" + correlation[1:], correlation + "0"} {
		if bad == "" {
			continue
		} // пустое значение обозначает уже существующее явное действие модератора
		if _, err := validateServerBridgeControlRequest0195("player.kick", map[string]string{"username": "Steve", "sessionCorrelationId": bad}); err == nil {
			t.Fatalf("invalid session correlation accepted: %q", bad)
		}
	}
	if _, err := validateServerBridgeControlRequest0195("ban.add", map[string]string{"username": "Steve", "sessionCorrelationId": correlation}); err == nil {
		t.Fatal("session correlation must not enlarge ban payload privileges")
	}
}

func TestServerBridgeControlSignature0195(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := canonicalControlPayload0195(map[string]string{"message": "hello"})
	sum := sha256.Sum256(payload)
	canonical := serverBridgeControlCanonical0195("paper-main", "ctl_test", "abc123", "message.broadcast", hex.EncodeToString(sum[:]), "0123456789abcdef0123456789abcdef", "lease_token_0123456789abcdef", 7, 11, 2, 1000, 2000)
	signature := ed25519.Sign(priv, []byte(canonical))
	if !ed25519.Verify(pub, []byte(canonical), signature) {
		t.Fatal("Корректная подпись управляющей команды ошибочно отклонена")
	}
	if ed25519.Verify(pub, []byte(canonical+"tampered"), signature) {
		t.Fatal("Подменённая подпись управляющей команды ошибочно принята")
	}
	if len(base64.RawURLEncoding.EncodeToString(signature)) != 86 {
		t.Fatal("unexpected Ed25519 encoding")
	}
}

func TestServerBridgeControlMemoryIdempotencyLeaseAndAck0195(t *testing.T) {
	runtimeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store := &serverBridgeStore{controlCommands: map[string]model.ServerBridgeControlCommand{}, controlIdempotency: map[string]string{}}
	now := time.Now().UTC()
	cmd := model.ServerBridgeControlCommand{ID: "ctl_one", ServerID: "paper-main", RuntimeEpoch: 9, RuntimeID: runtimeID, Type: "server.save", Payload: map[string]string{}, PayloadSHA256: "abc", RequestDigest: "request-1", RequestedBy: "admin@example.test", IdempotencyKey: "idem-12345678", Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Minute)}
	first, reused, err := store.createControl0195(cmd, now)
	if err != nil || reused || first.ID != cmd.ID {
		t.Fatalf("Создание: %+v, повторно использовано=%v, ошибка=%v", first, reused, err)
	}
	replay, reused, err := store.createControl0195(cmd, now)
	if err != nil || !reused || replay.ID != cmd.ID {
		t.Fatalf("idempotent replay: %+v reused=%v err=%v", replay, reused, err)
	}
	conflict := cmd
	conflict.ID = "ctl_two"
	conflict.RequestDigest = "request-2"
	if _, _, err := store.createControl0195(conflict, now); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Ожидался конфликт идемпотентности, получено %v", err)
	}
	channelID := "0123456789abcdef0123456789abcdef"
	leaseToken := "lease_token_0123456789abcdef"
	leased, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, channelID, leaseToken, 0, now, 30*time.Second)
	if err != nil || leased.Attempt != 1 || leased.Status != "leased" {
		t.Fatalf("Аренда: %+v, ошибка=%v", leased, err)
	}
	if _, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", channelID, "lease_token_other_0123456789", 0, now, 30*time.Second); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Команда не должна поступать в несоответствующий Runtime: %v", err)
	}
	resumed, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, channelID, "ignored_new_token_0123456789", 0, now.Add(time.Second), 30*time.Second)
	if err != nil || resumed.ID != leased.ID || resumed.Attempt != leased.Attempt || resumed.LeaseToken != leased.LeaseToken {
		t.Fatalf("Восстановление канала не вернуло прежнюю аренду: %+v ошибка=%v", resumed, err)
	}
	if _, err := store.leaseControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, "fedcba9876543210fedcba9876543210", "lease_token_other_0123456789", 0, now.Add(time.Second), 30*time.Second); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Конкурирующий активный канал получил арендованную команду: %v", err)
	}
	done, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(time.Second))
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("Завершение: %+v, ошибка=%v", done, err)
	}
	again, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "true"}, "", now.Add(2*time.Second))
	if err != nil || again.Status != "succeeded" {
		t.Fatalf("Идемпотентное подтверждение завершилось ошибкой: %+v ошибка=%v", again, err)
	}
	if _, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "succeeded", map[string]string{"saved": "false"}, "", now.Add(3*time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Принято подтверждение с тем же статусом, но противоречащим результатом: %v", err)
	}
	if _, err := store.completeControl0195(cmd.ServerID, cmd.RuntimeEpoch, runtimeID, cmd.ID, leased.LeaseOwner, leased.LeaseToken, leased.DeliverySequence, "failed", nil, "late conflict", now.Add(3*time.Second)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("Принято противоречащее подтверждение: %v", err)
	}
}
