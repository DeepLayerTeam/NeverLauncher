package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func updaterFixture0527(t *testing.T) (string, updaterFileSpec0156) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(t.TempDir(), "release-payload")
	if err := os.WriteFile(filepath.Join(root, "runtime.bin"), []byte("verified-previous-release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "world-save.dat"), []byte("user-owned-save"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("new-release-image"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, updaterTestSpec0156(t, "runtime.bin", src, true)
}

func TestUpdaterCrashChild0527(t *testing.T) {
	if os.Getenv("NL0527_UPDATER_CHILD") != "1" {
		return
	}
	root := os.Getenv("NL0527_ROOT")
	src := os.Getenv("NL0527_SOURCE")
	ready := os.Getenv("NL0527_READY")
	if root == "" || src == "" || ready == "" {
		t.Fatal("Отсутствуют входные параметры вспомогательного процесса")
	}
	u, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	spec := updaterTestSpec0156(t, "runtime.bin", src, true)
	_, err = u.apply(updaterRequest0156{Root: root, Namespace: "crash-restart-e2e", Files: []updaterFileSpec0156{spec}, Verify: func() error {
		if err := os.WriteFile(ready, []byte("after-live-swap"), 0600); err != nil {
			return err
		}
		select {} // родитель завершает *этот процесс* до записи фиксации в журнал.
	}})
	t.Fatalf("Процесс должен быть завершён до возврата: %v", err)
}

func TestUpdaterSigkillRecoveryPreservesUserBytes0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Завершение проверяется отдельным нативным испытателем сбоев Windows")
	}
	root, spec := updaterFixture0527(t)
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpdaterCrashChild0527$")
	cmd.Env = append(os.Environ(), "NL0527_UPDATER_CHILD=1", "NL0527_ROOT="+root, "NL0527_SOURCE="+spec.Source, "NL0527_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Реальный дочерний процесс не дошёл до проверки после замены")
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, err := os.ReadFile(filepath.Join(root, "runtime.bin"))
	if err != nil || string(raw) != "new-release-image" {
		t.Fatalf("Дочерний процесс не применил фактические байты: %q %v", raw, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	u, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := u.recover(false)
	if err != nil {
		t.Fatalf("Автоматическое восстановление транзакции после завершения процессом ОС: %v", err)
	}
	if len(report["recovered"].([]string)) != 1 {
		t.Fatalf("Отсутствует квитанция восстановления после сбоя: %+v", report)
	}
	got, err := os.ReadFile(filepath.Join(root, "runtime.bin"))
	if err != nil || string(got) != "verified-previous-release" {
		t.Fatalf("Откат не восстановил исходные байты: %s %v", got, err)
	}
	user, err := os.ReadFile(filepath.Join(root, "world-save.dat"))
	if err != nil || string(user) != "user-owned-save" {
		t.Fatalf("Сбой или восстановление повредили пользовательские данные: %q %v", user, err)
	}
	state, err := u.status()
	if err != nil || state["status"] != "idle" {
		t.Fatalf("Восстановление не перешло в состояние ожидания: %v %+v", err, state)
	}
}

func TestUpdaterDamagedBackupCannotPoisonRollback0527(t *testing.T) {
	root, spec := updaterFixture0527(t)
	u, _ := newTransactionalUpdater0156(root)
	if err := u.acquireLock(false); err != nil {
		t.Fatal(err)
	}
	defer u.releaseLock()
	j, err := u.prepareLocked(updaterRequest0156{Root: root, Namespace: "backup-integrity", Files: []updaterFileSpec0156{spec}})
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Touched) != 1 || j.Touched[0].OriginalSHA256 == "" {
		t.Fatalf("Контрольная сумма резервной копии не записана: %+v", j.Touched)
	}
	backup := filepath.Join(u.transactionDir(j.ID), "backup", "runtime.bin")
	if err := os.WriteFile(backup, []byte("attacker-replaced-backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := u.rollbackLocked(j, errors.New("untrusted-backup")); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("Принят откат с повреждёнными данными: %v", err)
	}
	old, _ := os.ReadFile(filepath.Join(root, "runtime.bin"))
	if string(old) != "verified-previous-release" {
		t.Fatalf("Повреждённая резервная копия заменила оригинал: %s", old)
	}
}

func TestUpdaterStagingFailureDoesNotRetainPayload0527(t *testing.T) {
	root, spec := updaterFixture0527(t)
	spec.SHA256 = strings.Repeat("0", 64) // корректно определять изменённый или повреждённый артефакт выпуска
	u, _ := newTransactionalUpdater0156(root)
	if _, err := u.apply(updaterRequest0156{Root: root, Namespace: "bad-hash", Files: []updaterFileSpec0156{spec}}); err == nil {
		t.Fatal("Повреждённый пакет зафиксирован")
	}
	got, _ := os.ReadFile(filepath.Join(root, "runtime.bin"))
	if string(got) != "verified-previous-release" {
		t.Fatalf("Повреждённый выпуск затронул установленные байты: %s", got)
	}
	dirs, err := os.ReadDir(filepath.Join(root, ".launcher", "updater", "transactions"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(root, ".launcher", "updater", "transactions", dir.Name(), "stage")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("После неудачной транзакции остались подготовленные данные: %v", err)
		}
	}
}

func TestUpdaterRefusesPreexistingSymlinkTemporary0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Требуется разрешение на создание символических ссылок POSIX")
	}
	root, spec := updaterFixture0527(t)
	sentinel := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(sentinel, []byte("not-an-updater-file"), 0600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "fake-updater-temp")
	if err := os.Symlink(sentinel, tmp); err != nil {
		t.Skip(err)
	}
	if err := copyUpdaterSource0156(spec.Source, tmp, 0600); err == nil {
		t.Fatal("Выполнен переход по временной символической ссылке, контролируемой атакующим")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "not-an-updater-file" {
		t.Fatalf("Перезаписан файл за пределами целевого каталога: %q %v", got, err)
	}
}

func TestUpdaterRecoversCrashDuringRollbackAndCleansTemps0527(t *testing.T) {
	root, spec := updaterFixture0527(t)
	u, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.acquireLock(false); err != nil {
		t.Fatal(err)
	}
	journal, err := u.prepareLocked(updaterRequest0156{Root: root, Namespace: "rollback-after-crash", Files: []updaterFileSpec0156{spec}})
	if err != nil {
		u.releaseLock()
		t.Fatal(err)
	}
	journal.Phase = "committing"
	if err := u.writeJournal(journal); err != nil {
		u.releaseLock()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime.bin"), []byte("incomplete-new-payload"), 0600); err != nil {
		u.releaseLock()
		t.Fatal(err)
	}
	leftovers := []string{filepath.Join(root, "runtime.bin.nl0156-"+journal.ID), filepath.Join(root, "runtime.bin.nl0156-rollback-"+journal.ID)}
	for _, file := range leftovers {
		if err := os.WriteFile(file, []byte("partially-copied-temp"), 0600); err != nil {
			u.releaseLock()
			t.Fatal(err)
		}
	}
	u.releaseLock()
	report, err := u.recover(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report["recovered"].([]string)) != 1 {
		t.Fatalf("Прерванный откат не восстановлен: %+v", report)
	}
	got, err := os.ReadFile(filepath.Join(root, "runtime.bin"))
	if err != nil || string(got) != "verified-previous-release" {
		t.Fatalf("Восстановлены неправильные данные: %q %v", got, err)
	}
	for _, file := range leftovers {
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("После сбоя остался временный файл: %s %v", file, err)
		}
	}
}
