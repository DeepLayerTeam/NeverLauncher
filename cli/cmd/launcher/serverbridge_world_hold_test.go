package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorldCohortGate0518HeldAcrossWorldBackupProcess(t *testing.T) {
	root := t.TempDir()
	release, err := worldBackupHostGateAcquire04110(root, "backup")
	if err != nil {
		t.Fatal(err)
	}
	runID := strings.Repeat("a", 32)
	backupID := strings.Repeat("b", 32)
	if err := worldBackupPersistCohortHold0518(root, runID, backupID); err != nil {
		release()
		t.Fatal(err)
	}
	if _, err := worldBackupHostGateAcquire04110(root, "start"); err == nil {
		t.Fatal("JVM мира запустилась во время блокировки контрольной точки")
	}
	if err := worldBackupReleaseCohortHold0518(root, strings.Repeat("c", 32)); err == nil {
		t.Fatal("другая группа резервных копий сняла блокировку мира")
	}
	if _, err := os.Stat(filepath.Join(worldBackupHostGatePath04110(root), worldCohortHoldFile0518)); err != nil {
		t.Fatalf("блокировка исчезла после ошибочного освобождения: %v", err)
	}
	if err := worldBackupReleaseCohortHold0518(root, runID); err != nil {
		t.Fatal(err)
	}
	next, err := worldBackupHostGateAcquire04110(root, "start")
	if err != nil {
		t.Fatalf("блокировка запуска JVM не снята: %v", err)
	}
	next()
}

func TestWorldBackupCommandRetainsCohortGate0518(t *testing.T) {
	root := writeWorldFixture02810(t)
	store := filepath.Join(t.TempDir(), "worlds")
	runID := strings.Repeat("d", 32)
	receipt := filepath.Join(t.TempDir(), "receipt.json")
	err := worldBackupHandle02810([]string{"create", "--server-root", root,
		"--backup-root", store, "--consistency", "stopped", "--world", "survival",
		"--hold-id", runID, "--output", receipt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worldBackupHostGateAcquire04110(root, "start"); err == nil {
		t.Fatal("мир смог перезапуститься между копированием мира и контрольной точкой БД")
	}
	if err := worldBackupHandle02810([]string{"release", "--server-root", root,
		"--backup-root", store, "--hold-id", runID}); err != nil {
		t.Fatal(err)
	}
	start, err := worldBackupHostGateAcquire04110(root, "start")
	if err != nil {
		t.Fatal(err)
	}
	start()
}
