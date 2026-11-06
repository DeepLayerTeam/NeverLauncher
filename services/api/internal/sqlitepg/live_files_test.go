package sqlitepg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func TestStoragePathsAndDigest0474(t *testing.T) {
	for _, path := range []string{"../escape", "/absolute", "x/../escape", "x\\windows", ".", "x//y"} {
		if _, err := filePath0474("p", "v", path); err == nil {
			t.Fatalf("Принято небезопасное значение %q", path)
		}
	}
	if _, err := filePath0474("p", "v", "mods/a.jar"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified payload")
	want := sha256.Sum256(payload)
	hash, n, err := fileDigest0474(context.Background(), bytes.NewReader(payload))
	if err != nil || n != int64(len(payload)) || hash != hex.EncodeToString(want[:]) {
		t.Fatalf("digest=%s size=%d err=%v", hash, n, err)
	}
	if err := context.Canceled; err == nil {
		t.Fatal("impossible")
	}
}
func TestAtomicVerifiedLocalFile0474(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := storage.NewLocalStorage(filepath.Join(dir, "src"))
	dest := storage.NewLocalStorage(filepath.Join(dir, "dest"))
	raw := bytes.Repeat([]byte("abcdef"), 4096)
	sum := sha256.Sum256(raw)
	obj := fileObject0474{"project", "release", "a/b.jar", hex.EncodeToString(sum[:]), int64(len(raw))}
	if _, _, err := source.Save(obj.project, obj.version, obj.path, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err := safeLocalObject0474(source, obj); err != nil {
		t.Fatal(err)
	}
	if err := atomicLocalSave0474(ctx, dest, obj, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	exists, err := verifyObject0474(ctx, dest, obj)
	if err != nil || !exists {
		t.Fatalf("readback: %v %v", exists, err)
	}
	if err := atomicLocalSave0474(ctx, dest, obj, bytes.NewReader(raw)); err == nil {
		t.Fatal("Перезаписан существующий объект")
	}
	corrupted := obj
	corrupted.hash = strings.Repeat("0", 64)
	if exists, err = verifyObject0474(ctx, dest, corrupted); !exists || err == nil {
		t.Fatal("Принята повреждённая контрольная сумма")
	}
	outside := filepath.Join(dir, "external.bin")
	if err = os.WriteFile(outside, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(dir, "src", "project", "release", "a", "linked.jar")); err == nil {
		symlink := obj
		symlink.path = "a/linked.jar"
		if e := safeLocalObject0474(source, symlink); e == nil {
			t.Fatal("Выполнен переход по символической ссылке источника")
		}
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
}
func TestStateConversionValidation0474(t *testing.T) {
	h := sha256.Sum256([]byte(`{"a":1}`))
	row := map[string]any{"payload": `{"a":1}`, "payload_digest": hex.EncodeToString(h[:])}
	if _, err := digestJSON0474(row, "payload", "payload_digest"); err != nil {
		t.Fatal(err)
	}
	row["payload"] = `{"a":2}`
	if _, err := digestJSON0474(row, "payload", "payload_digest"); err == nil {
		t.Fatal("Принято повреждение контрольной суммы")
	}
	names := map[string]bool{}
	for _, r := range stateRules0474() {
		if names[r.source] {
			t.Fatalf("duplicate %s", r.source)
		}
		names[r.source] = true
	}
	for _, name := range []string{"auth_sessions", "mfa_totp", "durable_jobs", "durable_outbox", "bridge_nonces"} {
		if !names[name] {
			t.Fatal("Отсутствует средство импорта состояния", name)
		}
	}
}
