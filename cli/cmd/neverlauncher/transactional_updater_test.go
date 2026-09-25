package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func updaterTestSpec0156(t *testing.T, rel, src string, executable bool) updaterFileSpec0156 {
	t.Helper()
	sum, size, err := hashFile(src)
	if err != nil {
		t.Fatal(err)
	}
	return updaterFileSpec0156{Path: rel, Source: src, Size: size, SHA256: sum, Executable: executable}
}

func TestTransactionalUpdaterCommitAndDelete0156(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "obsolete.bin"), []byte("obsolete"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app.bin"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "extra.bin"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := updater.apply(updaterRequest0156{
		Root:        root,
		Namespace:   "test",
		FromVersion: "1",
		ToVersion:   "2",
		Files: []updaterFileSpec0156{
			updaterTestSpec0156(t, "app.bin", filepath.Join(source, "app.bin"), false),
			updaterTestSpec0156(t, "extra.bin", filepath.Join(source, "extra.bin"), false),
		},
		Remove: []string{"obsolete.bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "committed" {
		t.Fatalf("report=%v", report)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "app.bin")); string(raw) != "new" {
		t.Fatalf("app.bin=%q", raw)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "extra.bin")); string(raw) != "extra" {
		t.Fatalf("extra.bin=%q", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "obsolete.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete file still exists: %v", err)
	}
	status, err := updater.status()
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "idle" {
		t.Fatalf("status=%v", status)
	}
}

func TestTransactionalUpdaterPostVerifyFailureRollsBack0156(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app.bin"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "created.bin"), []byte("created"), 0o644); err != nil {
		t.Fatal(err)
	}
	updater, _ := newTransactionalUpdater0156(root)
	_, err := updater.apply(updaterRequest0156{
		Root:      root,
		Namespace: "test-rollback",
		Files: []updaterFileSpec0156{
			updaterTestSpec0156(t, "app.bin", filepath.Join(source, "app.bin"), false),
			updaterTestSpec0156(t, "created.bin", filepath.Join(source, "created.bin"), false),
		},
		Verify: func() error { return errors.New("synthetic verification failure") },
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "app.bin")); string(raw) != "old" {
		t.Fatalf("rollback did not restore app.bin: %q", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "created.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback did not remove newly-created file: %v", err)
	}
}

func TestTransactionalUpdaterCrashRecovery0156(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app.bin"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	updater, _ := newTransactionalUpdater0156(root)
	if err := updater.acquireLock(false); err != nil {
		t.Fatal(err)
	}
	journal, err := updater.prepareLocked(updaterRequest0156{Root: root, Namespace: "crash", Files: []updaterFileSpec0156{updaterTestSpec0156(t, "app.bin", filepath.Join(source, "app.bin"), false)}})
	if err != nil {
		updater.releaseLock()
		t.Fatal(err)
	}
	journal.Phase = "committing"
	if err := updater.writeJournal(journal); err != nil {
		updater.releaseLock()
		t.Fatal(err)
	}
	stage := filepath.Join(updater.transactionDir(journal.ID), "stage", "app.bin")
	dst := filepath.Join(root, "app.bin")
	tmp := dst + ".crash-test"
	if err := copyUpdaterSource0156(stage, tmp, 0o644); err != nil {
		updater.releaseLock()
		t.Fatal(err)
	}
	if err := replaceFileAtomicPortable(tmp, dst); err != nil {
		updater.releaseLock()
		t.Fatal(err)
	}
	updater.releaseLock() // Simulate process death after a live-tree switch but before commit.

	if raw, _ := os.ReadFile(dst); string(raw) != "new" {
		t.Fatalf("crash simulation did not switch file: %q", raw)
	}
	report, err := updater.recover(false)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _ := report["recovered"].([]string)
	if len(recovered) != 1 || recovered[0] != journal.ID {
		t.Fatalf("recovery report=%v", report)
	}
	if raw, _ := os.ReadFile(dst); string(raw) != "old" {
		t.Fatalf("crash recovery did not restore original: %q", raw)
	}
}

func TestManifestUpdaterApply0156(t *testing.T) {
	root := t.TempDir()
	oldSource := filepath.Join(root, "old-source")
	newSource := filepath.Join(root, "new-source")
	live := filepath.Join(root, "live")
	for _, dir := range []string{oldSource, newSource, live} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(oldSource, "keep.txt"), "same")
	mustWrite(filepath.Join(oldSource, "replace.txt"), "old")
	mustWrite(filepath.Join(oldSource, "delete.txt"), "delete")
	mustWrite(filepath.Join(newSource, "keep.txt"), "same")
	mustWrite(filepath.Join(newSource, "replace.txt"), "new")
	mustWrite(filepath.Join(newSource, "add.txt"), "add")
	for _, name := range []string{"keep.txt", "replace.txt", "delete.txt"} {
		raw, err := os.ReadFile(filepath.Join(oldSource, name))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(filepath.Join(live, name), string(raw))
	}
	oldManifest, err := buildManifest(oldSource, "p", "vanilla", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	newManifest, err := buildManifest(newSource, "p", "vanilla", "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(root, "old.json")
	newPath := filepath.Join(root, "new.json")
	if err := writeJSONFile(oldPath, oldManifest); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(newPath, newManifest); err != nil {
		t.Fatal(err)
	}
	report, err := applyManifestUpdate0156(oldPath, newPath, newSource, live)
	if err != nil {
		t.Fatal(err)
	}
	if report["status"] != "committed" {
		t.Fatalf("report=%v", report)
	}
	if raw, _ := os.ReadFile(filepath.Join(live, "replace.txt")); string(raw) != "new" {
		t.Fatalf("replace.txt=%q", raw)
	}
	if raw, _ := os.ReadFile(filepath.Join(live, "add.txt")); string(raw) != "add" {
		t.Fatalf("add.txt=%q", raw)
	}
	if _, err := os.Stat(filepath.Join(live, "delete.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delete.txt still exists: %v", err)
	}
}

func TestTransactionalUpdaterRejectsTraversal0156(t *testing.T) {
	root := t.TempDir()
	updater, _ := newTransactionalUpdater0156(root)
	data := []byte("bad")
	size, sum := updaterBytesMetadata0156(data)
	_, err := updater.apply(updaterRequest0156{Root: root, Files: []updaterFileSpec0156{{Path: "../escape", Data: data, Size: size, SHA256: sum}}})
	if err == nil {
		t.Fatal("path traversal accepted")
	}
}
