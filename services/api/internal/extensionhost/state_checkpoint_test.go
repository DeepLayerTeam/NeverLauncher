package extensionhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointRestoresRealState04810(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	key := Key{ExtensionID: "example.state", Scope: "global"}
	dir := runtimeDir0303(root, key)
	file, err := runtimeFile0303(dir, "storage", "counter")
	if err != nil {
		t.Fatal(err)
	}
	if err = runtimeWrite0303(ctx, dir, file, []byte(`{"counter":3}`)); err != nil {
		t.Fatal(err)
	}
	tx := "extupd-012345678901234567890123"
	if err = snapshotRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatal(err)
	}
	// Версионированная миграция Java изменяет существующие документы и добавляет
	// новые.
	if err = runtimeWrite0303(ctx, dir, file, []byte(`{"counter":4}`)); err != nil {
		t.Fatal(err)
	}
	additional, _ := runtimeFile0303(dir, "config", "migration")
	if err = runtimeWrite0303(ctx, dir, additional, []byte(`true`)); err != nil {
		t.Fatal(err)
	}
	if err = restoreRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatal(err)
	}
	value, found, err := runtimeRead0303(dir, file)
	if err != nil || !found || string(value) != `{"counter":3}` {
		t.Fatalf("restore=%s found=%v err=%v", value, found, err)
	}
	if _, err = os.Stat(additional); !os.IsNotExist(err) {
		t.Fatalf("new document survived rollback: %v", err)
	}
	if err = restoreRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatalf("restore must be repeatable: %v", err)
	}
}
func TestCheckpointTamperRefusesOverwrite04810(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	key := Key{ExtensionID: "example.audit", Scope: "project", ScopeID: "p1"}
	dir := runtimeDir0303(root, key)
	file, _ := runtimeFile0303(dir, "config", "theme")
	if err := runtimeWrite0303(ctx, dir, file, []byte(`"dark"`)); err != nil {
		t.Fatal(err)
	}
	tx := "extupd-abcdefabcdefabcdefabcdef"
	if err := snapshotRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatal(err)
	}
	backup, _ := checkpointPath04810(root, key, tx)
	if err := os.WriteFile(filepath.Join(backup, filepath.Base(file)), []byte(`"light"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreRuntime04810(ctx, root, key, tx); err == nil {
		t.Fatal("Подменённая резервная копия ошибочно принята")
	}
	value, _, _ := runtimeRead0303(dir, file)
	if string(value) != `"dark"` {
		t.Fatal("restore damaged active data after checksum failure")
	}
}
func TestAbsentCheckpointIsolation04810(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	key := Key{ExtensionID: "example.state", Scope: "project", ScopeID: "a"}
	other := Key{ExtensionID: "example.state", Scope: "project", ScopeID: "b"}
	dir := runtimeDir0303(root, key)
	another := runtimeDir0303(root, other)
	file, _ := runtimeFile0303(dir, "storage", "state")
	outside, _ := runtimeFile0303(another, "storage", "state")
	if err := runtimeWrite0303(ctx, another, outside, []byte(`3`)); err != nil {
		t.Fatal(err)
	}
	tx := "extupd-000011112222333344445555"
	if err := snapshotRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatal(err)
	}
	if err := runtimeWrite0303(ctx, dir, file, []byte(`2`)); err != nil {
		t.Fatal(err)
	}
	if err := restoreRuntime04810(ctx, root, key, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("previously absent state directory exists: %v", err)
	}
	value, found, err := runtimeRead0303(another, outside)
	if err != nil || !found || string(value) != "3" {
		t.Fatal("other project changed")
	}
}
func TestCheckpointRejectsSymlinkAndInvalidID04810(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	key := Key{ExtensionID: "example.state", Scope: "global"}
	if err := snapshotRuntime04810(ctx, root, key, "../unsafe"); err == nil {
		t.Fatal("unsafe transaction ID accepted")
	}
	dir := runtimeDir0303(root, key)
	if err := secureDirectory0303(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "storage-"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")); err != nil {
		t.Skipf("символические ссылки не поддерживаются: %v", err)
	}
	if err := snapshotRuntime04810(ctx, root, key, "extupd-012301230123012301230123"); err == nil {
		t.Fatal("Состояние через символьную ссылку ошибочно принято")
	}
}
