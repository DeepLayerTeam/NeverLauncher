package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Регрессия: восстановление из частичной копии НЕ должно заявлять успех, когда
// список объектов БД содержит дополнительную активную текстуру.
func TestTextureGA0260RejectsIncompleteSnapshotBeforeMutation(t *testing.T) {
	ctx := context.Background()
	store := NewLocalStorage(t.TempDir())
	first := textureFixture0253([]byte("first immutable texture"))
	second := textureFixture0253([]byte("second immutable texture"))
	if _, _, err := PutTextureImmutable0253(ctx, store, first.Digest, []byte("first immutable texture")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PutTextureImmutable0253(ctx, store, second.Digest, []byte("second immutable texture")); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "snapshot")
	if err := BackupTextures0253(ctx, store, []TextureBackupObject0253{first}, backup); err != nil {
		t.Fatal(err)
	}
	if err := DeleteTexture0253(ctx, store, first.Digest); err != nil {
		t.Fatal(err)
	}
	if restored, err := RestoreTextures0253(ctx, store, backup, []TextureBackupObject0253{first, second}); err == nil || restored != 0 || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("Неполная резервная копия ошибочно принята: %d, %v", restored, err)
	}
	if f, _, err := OpenTexture0252(store, first.Digest); err == nil {
		f.Close()
		t.Fatal("Частичное восстановление изменило хранилище до авторизации манифеста")
	}
	if _, err := RestoreTextures0253(ctx, store, backup, []TextureBackupObject0253{first, first}); err == nil {
		t.Fatal("Принят повторяющийся перечень объектов")
	}
	if restored, err := RestoreTextures0253(ctx, store, backup, []TextureBackupObject0253{first}); err != nil || restored != 1 {
		t.Fatalf("Ошибка полного восстановления совпадающих данных: %d %v", restored, err)
	}
}

func TestTextureGA0260RejectsUnsafeManifest(t *testing.T) {
	ctx := context.Background()
	store := NewLocalStorage(t.TempDir())
	obj := textureFixture0253([]byte("manifest validation"))
	if _, _, err := PutTextureImmutable0253(ctx, store, obj.Digest, []byte("manifest validation")); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot")
	if err := BackupTextures0253(ctx, store, []TextureBackupObject0253{obj}, snapshot); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(snapshot, "manifest.json")
	backup, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "manifest-original")
	if err := os.WriteFile(outside, backup, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, manifest); err != nil {
		t.Skipf("символические ссылки недоступны: %v", err)
	}
	if _, err := RestoreTextures0253(ctx, store, snapshot, []TextureBackupObject0253{obj}); err == nil {
		t.Fatal("Принят манифест через символьную ссылку")
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(strings.Repeat("x", 16<<20+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTextures0253(ctx, store, snapshot, []TextureBackupObject0253{obj}); err == nil {
		t.Fatal("Принят манифест сверх допустимого размера")
	}
	if err := os.WriteFile(manifest, backup, 0600); err != nil {
		t.Fatal(err)
	}
	var broken textureBackupManifest0253
	if err := json.Unmarshal(backup, &broken); err != nil {
		t.Fatal(err)
	}
	broken.Objects = nil
	short, _ := json.Marshal(broken)
	if err := os.WriteFile(manifest, short, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreTextures0253(ctx, store, snapshot, []TextureBackupObject0253{obj}); err == nil {
		t.Fatal("Принят пустой манифест для непустого учёта объектов")
	}
}
