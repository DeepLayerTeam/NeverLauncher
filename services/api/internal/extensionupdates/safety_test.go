package extensionupdates

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func TestUpdateHealthRequiresExactRunningGeneration0499(t *testing.T) {
	install := model.ExtensionInstall{ExtensionID: "example.plugin", Scope: "project", ScopeID: "p1", CurrentVersion: "2.0.0", Generation: 3}
	valid := extensionhost.Status{ExtensionID: "example.plugin", Scope: "project", ScopeID: "p1", Version: "2.0.0", Generation: 3, State: "running", Healthy: true}
	if !healthyInstallation0499(valid, install) {
		t.Fatal("Отклонена корректная активная версия")
	}
	invalid := []struct {
		name   string
		change func(*extensionhost.Status)
	}{
		{"previous-version", func(s *extensionhost.Status) { s.Version = "1.0.0" }},
		{"previous-generation", func(s *extensionhost.Status) { s.Generation = 2 }},
		{"different-project", func(s *extensionhost.Status) { s.ScopeID = "p2" }},
		{"different-extension", func(s *extensionhost.Status) { s.ExtensionID = "elsewhere" }},
		{"stopping", func(s *extensionhost.Status) { s.State = "stopping" }},
		{"unhealthy", func(s *extensionhost.Status) { s.Healthy = false }},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			got := valid
			tc.change(&got)
			if healthyInstallation0499(got, install) {
				t.Fatal("Принята посторонняя или устаревшая JVM")
			}
		})
	}
}

type stoppedHost0499 struct {
	fakeHost02011
	stopCount, failAt int
	startFailAt       int
	order             []string
}

func (h *stoppedHost0499) Stop(_ context.Context, k extensionhost.Key) error {
	h.stopCount++
	h.order = append(h.order, k.ExtensionID)
	if h.stopCount == h.failAt {
		return errors.New("simulated unkillable JVM")
	}
	return h.fakeHost02011.Stop(context.Background(), k)
}
func (h *stoppedHost0499) StartInstallation(ctx context.Context, ins model.ExtensionInstall) error {
	h.starts++
	if h.starts == h.startFailAt {
		return errors.New("simulated old JVM restart failure")
	}
	h.active = ins
	return nil
}

func TestRecoveryRefusesRestoreWhenJVMCannotStop0499(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	life := &fakeLifecycle02011{repo: r}
	if _, err := life.Update(ctx, target, extensionlifecycle.Scope{Scope: "global"}); err != nil {
		t.Fatal(err)
	}
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true, content: `{"schema":2}`, checkpoint: `{"schema":1}`}, failAt: 2}
	m := &Manager{Repo: r, Lifecycle: life, Host: h}
	tx := model.ExtensionUpdateTransaction{ID: "extupd-111111111111111111111111", Scope: "global", Status: "running", StartedAt: time.Now().UTC(), Plan: model.ExtensionUpdatePlan{
		Scope: "global", StateSnapshots: []string{"update.test"}, Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", Operation: "update", FromVersion: "1.0.0", ToVersion: "2.0.0"}}}, Applied: []string{"update.test"}}
	if _, err := r.SaveExtensionUpdateTransaction(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := m.recoverTransaction02011(ctx, tx, 30*time.Millisecond); err == nil || !strings.Contains(err.Error(), "cannot stop") {
		t.Fatalf("Восстановление должно отклонять работающий хост: %v", err)
	}
	if h.restores != 0 || h.content != `{"schema":2}` {
		t.Fatalf("Перезаписано новое состояние JVM: восстановлений=%d содержимое=%s", h.restores, h.content)
	}
	current, _ := r.GetExtensionInstallState(ctx, "update.test", "global", "")
	if current.CurrentVersion != "2.0.0" {
		t.Fatal("Пакет откатан при потенциально работающей JVM")
	}
	stored, _ := r.GetExtensionUpdateTransaction(ctx, tx.ID)
	if stored.Status != "running" {
		t.Fatalf("Журнал должен оставаться пригодным для восстановления: %s", stored.Status)
	}
}

type failedReadRepository0499 struct{ repository.Repository }

func (r failedReadRepository0499) GetExtensionInstallState(context.Context, string, string, string) (model.ExtensionInstall, error) {
	return model.ExtensionInstall{}, errors.New("database connection lost")
}
func TestRecoveryDoesNotSilentlySkipDatabaseError0499(t *testing.T) {
	ctx := context.Background()
	r, _, _ := updateFixture02011(t)
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true}}
	m := &Manager{Repo: failedReadRepository0499{r}, Lifecycle: &fakeLifecycle02011{r}, Host: h}
	tx := model.ExtensionUpdateTransaction{ID: "extupd-222222222222222222222222", Scope: "global", Status: "running", StartedAt: time.Now().UTC(), Plan: model.ExtensionUpdatePlan{
		Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", Operation: "unchanged", FromVersion: "1.0.0", ToVersion: "1.0.0"}}}}
	err := m.recoverTransaction02011(ctx, tx, 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "database connection lost") {
		t.Fatalf("Ошибка базы данных ошибочно признана успешным откатом: %v", err)
	}
}

func TestRecoveryStopsDependentsBeforeDependencies0499(t *testing.T) {
	ctx := context.Background()
	r, _, _ := updateFixture02011(t)
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true}}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{r}, Host: h}
	tx := model.ExtensionUpdateTransaction{ID: "extupd-333333333333333333333333", Scope: "global", Status: "running", StartedAt: time.Now().UTC(), Plan: model.ExtensionUpdatePlan{
		Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "base", Operation: "unchanged"}, {ExtensionID: "dependent", Operation: "unchanged"}}}}
	if err := m.recoverTransaction02011(ctx, tx, 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(h.order) != 2 || h.order[0] != "dependent" || h.order[1] != "base" {
		t.Fatalf("Неправильный порядок остановки: %v", h.order)
	}
}

func TestFailedOldJVMRestartRemainsRecoverable0499(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true}, failAt: 1, startFailAt: 1}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{r}, Host: h, Config: Config{HealthTimeout: 50 * time.Millisecond}}
	plan := model.ExtensionUpdatePlan{Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update"}}}
	tx, err := m.Apply(ctx, plan)
	if err == nil || tx.Status != "rollback_failed" {
		t.Fatalf("Небезопасное успешное прерывание: статус=%s ошибка=%v", tx.Status, err)
	}
	state, _ := r.GetExtensionInstallState(ctx, "update.test", "global", "")
	if state.CurrentVersion != "1.0.0" {
		t.Fatal("Пакет изменён до контрольной точки")
	}
	h.failAt = 0
	h.startFailAt = 0
	if err := m.recoverInterrupted02011(ctx, "global", "", time.Second); err != nil {
		t.Fatalf("Неудачная транзакция до изменения данных не поддаётся восстановлению: %v", err)
	}
	stored, err := r.GetExtensionUpdateTransaction(ctx, tx.ID)
	if err != nil || stored.Status != "rolled_back" {
		t.Fatalf("Неверно восстановленный журнал: %+v %v", stored, err)
	}
}

func TestApplyRejectsStaleUnchangedDependency0499(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true}}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{r}, Host: h}
	plan := model.ExtensionUpdatePlan{Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "2.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "unchanged"}}}
	tx, err := m.Apply(ctx, plan)
	if err == nil || !errors.Is(err, repository.ErrConflict) || tx.Status != "failed" {
		t.Fatalf("Ошибочно принята устаревшая зависимость: %+v %v", tx, err)
	}
	if h.stopCount != 0 {
		t.Fatal("JVM остановлена до проверки устаревшей зависимости")
	}
}

func TestApplyRejectsDuplicateModuleID0499(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	h := &stoppedHost0499{fakeHost02011: fakeHost02011{healthy: true}}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{r}, Host: h}
	item := model.ExtensionUpdatePlanItem{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update"}
	tx, err := m.Apply(ctx, model.ExtensionUpdatePlan{Scope: "global", Items: []model.ExtensionUpdatePlanItem{item, item}})
	if err == nil || !errors.Is(err, repository.ErrConflict) || tx.Status != "failed" {
		t.Fatalf("Повторяющийся модуль ошибочно принят: %+v %v", tx, err)
	}
	if h.stopCount != 0 {
		t.Fatal("JVM остановлена до проверки дубликата модуля")
	}
}

func TestRollbackCannotClaimSuccessWithUnhealthyOldJVM0499(t *testing.T) {
	ctx := context.Background()
	r, target, _ := updateFixture02011(t)
	h := &fakeHost02011{healthy: false, content: `{"schema":1}`}
	m := &Manager{Repo: r, Lifecycle: &fakeLifecycle02011{r}, Host: h, Config: Config{HealthTimeout: 25 * time.Millisecond}}
	plan := model.ExtensionUpdatePlan{Scope: "global", Items: []model.ExtensionUpdatePlanItem{{ExtensionID: "update.test", FromVersion: "1.0.0", ToVersion: "2.0.0", PackageIdentity: target.Artifact.PackageIdentity, Operation: "update"}}}
	tx, err := m.Apply(ctx, plan)
	if err == nil || tx.Status != "rollback_failed" || !strings.Contains(tx.Failure, "restored JVM unhealthy") {
		t.Fatalf("Небезопасное завершение отката: статус=%s сбой=%s ошибка=%v", tx.Status, tx.Failure, err)
	}
	h.healthy = true
	if err := m.recoverInterrupted02011(ctx, "global", "", time.Second); err != nil {
		t.Fatalf("Повторная попытка после восстановления: %v", err)
	}
	stored, err := r.GetExtensionUpdateTransaction(ctx, tx.ID)
	if err != nil || stored.Status != "rolled_back" {
		t.Fatalf("Откат не был восстановлен: %+v %v", stored, err)
	}
}
