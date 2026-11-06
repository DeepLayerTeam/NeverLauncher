package extensionhost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Эти тесты выполняют настоящий упакованный JAR-расширение Java 17+, а не имитацию хоста.
// Тестовый Java-хост имеет ограниченные сроки запуска и остановки и закрывается при очистке.
func persistJavaInstall0422(t *testing.T, host *Supervisor, install model.ExtensionInstall) model.ExtensionInstall {
	t.Helper()
	ctx := context.Background()
	saved, err := host.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID,
		DesiredVersion: install.CurrentVersion, CurrentVersion: install.CurrentVersion,
		DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
		PackageIdentity: "sha256:" + strings.Repeat("a", 64), CurrentPackageIdentity: "sha256:" + strings.Repeat("a", 64),
		Enabled: true, Source: "java-recovery-test", Operation: "enable", ExpectedGeneration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestJavaJvmCrashRestartsRealProcess0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 23*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	before, err := host.Get(key)
	if err != nil || !before.Healthy {
		t.Fatalf("Не удалось запустить JVM: %+v %v", before, err)
	}
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	until := time.NewTimer(17 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		after, err := host.Get(key)
		if err == nil && after.Healthy && after.InstanceID != before.InstanceID && after.PID != before.PID && after.Restarts >= 1 {
			result, err := host.CallJavaRPC0304(ctx, key, "health", nil)
			if err != nil || !strings.Contains(string(result), `"responsive":true`) {
				t.Fatalf("Перезапущенная JVM не принимает аутентифицированные RPC: %s: %v", result, err)
			}
			return
		}
		select {
		case <-tick.C:
		case <-until.C:
			t.Fatalf("Рабочая JVM не восстановилась: до=%+v после=%+v ошибка=%v", before, after, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestJavaMissingRuntimeRetryAfterRepair0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	missing := filepath.Join(t.TempDir(), "java-repaired")
	host.cfg.JavaExecutable = missing
	if err := host.StartInstallation(ctx, install); err == nil {
		t.Fatal("Неожиданно запущена недоступная JVM")
	}
	failed, err := host.Get(key)
	if err != nil || failed.State != "failed" || failed.LastError == "" {
		t.Fatalf("После неудачного запуска осталась устаревшая запись о запуске: %+v %v", failed, err)
	}
	if len(host.tokens) != 0 {
		t.Fatal("После сбоя JVM сохранила активный токен аутентификации")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("Java недоступна")
	}
	if err := os.WriteFile(missing, []byte("#!/bin/sh\nexec "+java+" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatalf("Восстановленную JVM не удалось запустить: %v", err)
	}
	running, err := host.Get(key)
	if err != nil || !running.Healthy || running.InstanceID == failed.InstanceID {
		t.Fatalf("Повторная попытка не выполняется: %+v %v", running, err)
	}
	if err := host.Stop(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestJavaReconcileRunningAndDisable0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	original, err := host.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if errs := host.Reconcile(ctx); len(errs) != 0 {
			t.Fatalf("Ошибка идемпотентного согласования %d: %v", i, errs)
		}
		current, _ := host.Get(key)
		if current.InstanceID != original.InstanceID || current.PID != original.PID {
			t.Fatalf("Согласование повторно запустило исправную JVM: %+v", current)
		}
	}
	_, err = host.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: key.ExtensionID, Scope: key.Scope, ScopeID: key.ScopeID,
		DesiredVersion: install.CurrentVersion, CurrentVersion: install.CurrentVersion,
		DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
		PackageIdentity: install.PackageIdentity, CurrentPackageIdentity: install.CurrentPackageIdentity,
		Enabled: false, Source: "java-recovery-test", Operation: "disable", ExpectedGeneration: install.Generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if errs := host.Reconcile(ctx); len(errs) != 0 {
		t.Fatalf("Ошибка согласования отключения: %v", errs)
	}
	stopped, err := host.Get(key)
	if err != nil || stopped.State != "stopped" {
		t.Fatalf("Отключённое расширение продолжает работать: %+v %v", stopped, err)
	}
}

func TestJavaStopCancelsScheduledRestart0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	before, _ := host.Get(key)
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := host.Get(key)
		if st.State == "crashed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := host.Stop(ctx, key); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // больше секундной паузы перед повторной попыткой
	after, _ := host.Get(key)
	if after.InstanceID != before.InstanceID || after.State == "running" {
		t.Fatalf("Команда оператора Stop не отменила перезапуск: %+v", after)
	}
}

// Отсутствующий исполняемый файл Java после сбоя не должен навсегда блокировать
// включённое расширение. Супервизор повторяет неудачные запуски ОС и в итоге
// запускает настоящий JAR, когда Java снова становится доступна.
func TestJavaAutoRecoveryAfterRuntimeRestored0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("среда выполнения Java недоступна")
	}
	wrapper := filepath.Join(t.TempDir(), "java-runtime")
	writeWrapper := func() error { return os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+java+" \"$@\"\n"), 0700) }
	if err := writeWrapper(); err != nil {
		t.Fatal(err)
	}
	host.cfg.JavaExecutable = wrapper
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	first, _ := host.Get(key)
	if err := os.Remove(wrapper); err != nil {
		t.Fatal(err)
	}
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	failDeadline := time.NewTimer(10 * time.Second)
	defer failDeadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	failed := false
	for !failed {
		status, _ := host.Get(key)
		if status.State == "failed" && status.InstanceID != first.InstanceID {
			failed = true
			break
		}
		select {
		case <-ticker.C:
		case <-failDeadline.C:
			t.Fatalf("При отсутствии Java Runtime состояние ошибки не установлено: %+v", status)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := writeWrapper(); err != nil {
		t.Fatal(err)
	}
	for {
		status, _ := host.Get(key)
		if status.Healthy && status.InstanceID != first.InstanceID && status.Restarts >= 2 {
			if _, err := host.CallJavaRPC0304(ctx, key, "health", nil); err != nil {
				t.Fatalf("RPC восстановленной JVM: %v", err)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("JVM не восстановилась после восстановления Java: %+v: %v", status, ctx.Err())
		}
	}
}
