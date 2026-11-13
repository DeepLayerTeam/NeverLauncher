package sqlitecore

import (
	"context"
	"path/filepath"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func TestCore0472MigratesVersion326AndDoesNotRepeatBackup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "core.sqlite")
	r, err := Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	project(t, r)
	profile(t, r)
	if err = r.store.Write(ctx, func(q sqlitedurable.Executor) error { _, e := q.ExecContext(ctx, "PRAGMA user_version=326"); return e }); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	counts, err := r.Count(ctx)
	if err != nil || counts["projects"] != 1 || counts["profiles"] != 1 {
		t.Fatalf("Потеряны основные записи: %v %v", counts, err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if len(backups) != 1 {
		t.Fatalf("Отсутствует резервная копия: %v", backups)
	}
	if _, err = sqlitedurable.VerifyBackup(ctx, backups[0]); err != nil {
		t.Fatal(err)
	}
	r, err = Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	backups, _ = filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if len(backups) != 1 {
		t.Fatal("Повторная миграция создала резервную копию")
	}
}
