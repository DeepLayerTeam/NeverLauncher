package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorldBackupGateBlocksStartAndSecondBackup04110(t *testing.T) {
	root := writeWorldFixture02810(t)
	release, err := worldBackupHostGateAcquire04110(root, "backup")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := worldBackupHostGateAcquire04110(root, "start"); err == nil {
		t.Fatal("JVM start entered backup gate")
	}
	if _, err := worldBackupHostGateAcquire04110(root, "backup"); err == nil {
		t.Fatal("second backup entered gate")
	}
	if err := worldBackupHostGateRecover04110(root); err == nil {
		t.Fatal("live owner gate recovered")
	}
	release()
	releaseStart, err := worldBackupHostGateAcquire04110(root, "start")
	if err != nil {
		t.Fatal(err)
	}
	releaseStart()
}

func TestWorldBackupGateFailsClosedAndRecoversOffline04110(t *testing.T) {
	root := writeWorldFixture02810(t)
	gate := worldBackupHostGatePath04110(root)
	if err := os.MkdirAll(gate, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := worldBackupHostGateAcquire04110(root, "start"); err == nil {
		t.Fatal("unreadable gate admitted a start")
	}
	if err := worldBackupHostGateRecover04110(root); err == nil {
		t.Fatal("unreadable gate was automatically reclaimed")
	}
	owner := worldHostGate04110{PID: 999999999, ProcessIdentity: "definitely-stale", Purpose: "backup", CreatedAt: "2026-01-01T00:00:00Z"}
	raw, _ := json.Marshal(owner)
	if err := os.WriteFile(filepath.Join(gate, "owner.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// An orphaned JVM still blocks unlocking a previous crashed backup.
	paths := hostPaths01910(root)
	runtime := serverBridgeHostRuntime01910{SchemaVersion: "1.0", Status: "running", ProcessPID: os.Getpid(), ProcessIdentity: hostOwnIdentity0282()}
	if err := atomicWriteJSON01910(paths["runtime"], runtime, 0600); err != nil {
		t.Fatal(err)
	}
	if err := worldBackupHostGateRecover04110(root); err == nil {
		t.Fatal("recovered gate despite live JVM")
	}
	if err := os.Remove(paths["runtime"]); err != nil {
		t.Fatal(err)
	}
	if err := worldBackupHostGateRecover04110(root); err != nil {
		t.Fatal(err)
	}
	release, err := worldBackupHostGateAcquire04110(root, "start")
	if err != nil {
		t.Fatal(err)
	}
	release()
}
