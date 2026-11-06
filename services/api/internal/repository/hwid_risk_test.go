package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestHWIDMemoryObservationAppealAndRecovery0299(t *testing.T) {
	r := NewMemoryRepository("https://test.invalid")
	now := time.Now().UTC()
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d1", UserID: "u1", Status: "active", TrustState: "verified"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	first, err := r.ObserveHWID0299(ctx, "u1", "d1", a, now)
	if err != nil || first.State != "recognized" {
		t.Fatalf("Начальное состояние: %#v %v", first, err)
	}
	same, err := r.ObserveHWID0299(ctx, "u1", "d1", a, now.Add(time.Second))
	if err != nil || same.State != "recognized" {
		t.Fatalf("Повторная проверка: %#v %v", same, err)
	}
	changed, err := r.ObserveHWID0299(ctx, "u1", "d1", b, now.Add(2*time.Second))
	if err != nil || changed.State != "changed" || changed.Baseline != a || changed.Pending != b {
		t.Fatalf("Изменённое состояние: %#v %v", changed, err)
	}
	if _, err := r.ObserveHWID0299(ctx, "u2", "d1", a, now); err == nil {
		t.Fatal("Разрешено наблюдение между учётными записями")
	}
	p := PublicHWIDState0299(changed)
	if strings.Contains(strings.Join([]string{p["state"].(string), p["deviceId"].(string)}, ":"), a) {
		t.Fatal("Произошла утечка хеша")
	}
	appeal := HWIDAppeal0299{ID: "appeal-1", UserID: "u1", DeviceID: "d1", Reason: "Replaced motherboard", CreatedAt: now.Add(3 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, appeal); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmitHWIDAppeal0299(ctx, appeal); err == nil {
		t.Fatal("Принято дублирующее ожидающее рассмотрения обращение")
	}
	resolved, err := r.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(4*time.Second))
	if err != nil || resolved.Status != "approved" {
		t.Fatalf("Обращение: %#v %v", resolved, err)
	}
	v, err := r.GetHWID0299(ctx, "u1", "d1", now.Add(5*time.Second))
	if err != nil || v.Baseline != b || v.Pending != "" || v.State != "recognized" {
		t.Fatalf("Восстановление: %#v %v", v, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, appeal.ID, "admin", "approved", now.Add(6*time.Second)); err == nil {
		t.Fatal("Разрешено повторное использование обращения")
	}
	if err := r.ForgetHWID0299(ctx, "u1", "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetHWID0299(ctx, "u1", "d1", now); err != ErrNotFound {
		t.Fatalf("Удаление персональных данных: %v", err)
	}
	appeals, _ := r.ListHWIDAppeals0299(ctx, "u1")
	if len(appeals) != 0 {
		t.Fatal("Обращения не удалены")
	}
}
func TestHWIDExpiryDoesNotLeaveActiveRisk0299(t *testing.T) {
	r := NewMemoryRepository("")
	now := time.Now().UTC()
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d", UserID: "u", Status: "active"})
	r.deviceMu.Unlock()
	_, err := r.ObserveHWID0299(context.Background(), "u", "d", strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.GetHWID0299(context.Background(), "u", "d", now.Add(31*24*time.Hour)); err != ErrNotFound {
		t.Fatalf("Подсказка с истёкшим сроком всё ещё активна: %v", err)
	}
	if err = r.PruneHWID0299(context.Background(), now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.hwidObservations) != 0 {
		t.Fatal("Просроченная подсказка не удалена")
	}
}

// Изменившийся сигнал хоста — недоверенная подсказка, но после обнаружения нельзя
// очищать её повтором старого сигнала. Решения проверки привязаны к кандидату.
func TestHWIDChangeIsStickyAndAppealCannotBeReplayed0433(t *testing.T) {
	r := NewMemoryRepository("https://test.invalid")
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "device", UserID: "owner", Status: "active", TrustState: "verified"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	now := time.Now().UTC()
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if _, err := r.ObserveHWID0299(ctx, "owner", "device", a, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ObserveHWID0299(ctx, "owner", "device", b, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	old, err := r.ObserveHWID0299(ctx, "owner", "device", a, now.Add(2*time.Second))
	if err != nil || old.State != "changed" || old.Pending != b || !old.UpdatedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("Повтор старого базового состояния снял или переместил событие риска: %#v %v", old, err)
	}
	first := HWIDAppeal0299{ID: "first", UserID: "owner", DeviceID: "device", Reason: "Changed mainboard", CreatedAt: now.Add(3 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, first); err != nil {
		t.Fatal(err)
	}
	next, err := r.ObserveHWID0299(ctx, "owner", "device", c, now.Add(4*time.Second))
	if err != nil || next.State != "changed" || next.Pending != c {
		t.Fatalf("Предложенное новое оборудование: %#v %v", next, err)
	}
	appeals, err := r.ListHWIDAppeals0299(ctx, "owner")
	if err != nil || len(appeals) != 1 || appeals[0].Status != "rejected" || appeals[0].Resolution != "superseded" {
		t.Fatalf("Обращение не признано недействительным: %#v %v", appeals, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "first", "admin", "approved", now.Add(5*time.Second)); err != ErrConflict {
		t.Fatalf("Подтверждение устаревшего обращения: %v", err)
	}
	if _, err := r.ConfirmHWID0299(ctx, "owner", "device", b, now.Add(5*time.Second)); err != ErrNotFound {
		t.Fatalf("Принято устаревшее подтверждение: %v", err)
	}
	second := HWIDAppeal0299{ID: "second", UserID: "owner", DeviceID: "device", Reason: "Another replacement", CreatedAt: now.Add(6 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "second", "admin", "rejected", now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	afterReject, err := r.GetHWID0299(ctx, "owner", "device", now.Add(8*time.Second))
	if err != nil || afterReject.State != "changed" {
		t.Fatalf("Отклонение сняло риск: %#v %v", afterReject, err)
	}
	third := HWIDAppeal0299{ID: "third", UserID: "owner", DeviceID: "device", Reason: "Additional evidence", CreatedAt: now.Add(9 * time.Second)}
	if err := r.SubmitHWIDAppeal0299(ctx, third); err != nil {
		t.Fatal(err)
	}
	confirmed, err := r.ConfirmHWID0299(ctx, "owner", "device", c, now.Add(10*time.Second))
	if err != nil || confirmed.State != "recognized" || confirmed.Baseline != c {
		t.Fatalf("Подтверждение владельца: %#v %v", confirmed, err)
	}
	if _, err := r.ResolveHWIDAppeal0299(ctx, "third", "admin", "approved", now.Add(11*time.Second)); err != ErrConflict {
		t.Fatalf("Подтверждённое владельцем обращение остаётся активным: %v", err)
	}
	appeals, _ = r.ListHWIDAppeals0299(ctx, "owner")
	for _, a := range appeals {
		if a.ID == "third" && a.Resolution != "confirmed-by-owner" {
			t.Fatalf("Потерян результат рассмотрения обращения: %#v", a)
		}
	}
	if _, err := r.ConfirmHWID0299(ctx, "owner", "device", c, now.Add(12*time.Second)); err != ErrNotFound {
		t.Fatalf("Повторное использование подтверждения: %v", err)
	}
}

func TestHWIDPendingReplayAndForget0433(t *testing.T) {
	r := NewMemoryRepository("")
	r.deviceMu.Lock()
	r.trustedDevices = append(r.trustedDevices, model.TrustedDevice{ID: "d", UserID: "u", Status: "active"})
	r.deviceMu.Unlock()
	ctx := context.Background()
	now := time.Now().UTC()
	a, b := strings.Repeat("1", 64), strings.Repeat("2", 64)
	_, _ = r.ObserveHWID0299(ctx, "u", "d", a, now)
	_, _ = r.ObserveHWID0299(ctx, "u", "d", b, now.Add(time.Second))
	for i := 0; i < 8; i++ {
		state, err := r.ObserveHWID0299(ctx, "u", "d", a, now.Add(time.Duration(i+2)*time.Second))
		if err != nil || state.State != "changed" || state.Pending != b {
			t.Fatalf("Повтор %d: %#v %v", i, state, err)
		}
	}
	if err := r.ForgetHWID0299(ctx, "u", "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetHWID0299(ctx, "u", "d", now); err != ErrNotFound {
		t.Fatalf("Не удалось удалить персональные данные: %v", err)
	}
}
