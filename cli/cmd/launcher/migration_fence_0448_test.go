package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeFencer0448(ctx context.Context, args ...string) (string, error) {
	switch args[0] {
	case "mask":
		return "", nil
	case "show":
		if strings.Contains(args[1], "ActiveState") {
			return "inactive", nil
		}
		return "masked-runtime", nil
	}
	return "", nil
}
func TestFenceSourceAndFreshSnapshot0448(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source-state.json")
	state := sourceFenceState0448{Format: "never/gravit-source-stop/v1", RunID: "run-11112222", ProfileID: "client", Channel: "stable", StageID: "stage-12345678901234", Unit: "gravit.service"}
	if err := stopSourceWriter0448(context.Background(), state, path, fakeFencer0448); err != nil {
		t.Fatal(err)
	}
	if err := stopSourceWriter0448(context.Background(), state, path, fakeFencer0448); err == nil {
		t.Fatal("overwrote stop receipt")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("stop evidence permissions: %v %v", st, err)
	}
	snapshotPath := filepath.Join(dir, "snapshot.json")
	// Same canonical field order as the API SnapshotDigest.
	snapshot := `{"worldSha256":"` + strings.Repeat("a", 64) + `","loader":"fabric","optionalPresetSha256":"` + strings.Repeat("b", 64) + `","players":[]}`
	if err := os.WriteFile(snapshotPath, []byte(snapshot), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(snapshot))
	expected := hex.EncodeToString(sum[:])
	receipt := filepath.Join(dir, "fence-receipt.json")
	report, err := verifyStoppedSource0448(context.Background(), path, snapshotPath, expected, receipt, fakeFencer0448)
	if err != nil {
		t.Fatal(err)
	}
	if report.SnapshotSHA256 != expected || report.UnitState != "inactive" {
		t.Fatalf("invalid receipt: %+v", report)
	}
	var loaded sourceFenceEvidence0448
	if err := readFenceFile0448(receipt, 4096, &loaded); err != nil || loaded.Unit != "gravit.service" {
		t.Fatalf("not round-tripped: %+v %v", loaded, err)
	}
	if _, err := verifyStoppedSource0448(context.Background(), path, snapshotPath, expected, receipt, fakeFencer0448); err == nil {
		t.Fatal("overwrote fence evidence")
	}
}
func TestFenceRejectsDriftAndWriterRestart0448(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := sourceFenceState0448{Format: "never/gravit-source-stop/v1", RunID: "run-11112222", ProfileID: "client", Channel: "stable", StageID: "stage-12345678901234", Unit: "gravit.service"}
	if err := stopSourceWriter0448(context.Background(), state, path, fakeFencer0448); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(snap, []byte(`{"worldSha256":"changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	expected := strings.Repeat("a", 64)
	if _, err := verifyStoppedSource0448(context.Background(), path, snap, expected, filepath.Join(dir, "proof"), fakeFencer0448); err == nil {
		t.Fatal("accepted changed world")
	}
	restarted := func(ctx context.Context, args ...string) (string, error) {
		if len(args) > 1 && strings.Contains(args[1], "ActiveState") {
			return "active", nil
		}
		return "masked-runtime", nil
	}
	if _, err := verifyStoppedSource0448(context.Background(), path, snap, expected, filepath.Join(dir, "proof"), restarted); err == nil {
		t.Fatal("accepted active source writer")
	}
	state.Unit = "../bad.service"
	if err := stopSourceWriter0448(context.Background(), state, filepath.Join(dir, "bad"), fakeFencer0448); err == nil {
		t.Fatal("allowed unsafe unit")
	}
	state.Unit = "gravit.service"
	state.StoppedAt = time.Now().Add(-20 * time.Minute)
	raw, _ := json.Marshal(state)
	old := filepath.Join(dir, "old.json")
	if err := os.WriteFile(old, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStoppedSource0448(context.Background(), old, snap, expected, filepath.Join(dir, "proof"), fakeFencer0448); err == nil {
		t.Fatal("accepted expired state")
	}
}
