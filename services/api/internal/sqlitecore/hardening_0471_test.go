package sqlitecore

import (
	"context"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteCore0471RejectsUnversionedForeignDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		if strings.Contains(err.Error(), "unsupported SQLite filesystem") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `CREATE TABLE unrelated_table (id TEXT PRIMARY KEY)`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if repo, e := Open(ctx, sqlitedurable.Options{Path: path}); e == nil {
		_ = repo.Close()
		t.Fatal("foreign schema silently changed")
	}
}

func TestSQLiteCore0471ExistingMustNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-db.sqlite")
	if repo, err := OpenExisting(context.Background(), sqlitedurable.Options{Path: path}); err == nil {
		_ = repo.Close()
		t.Fatal("created absent database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("OpenExisting created a database or unexpected error: %v", err)
	}
}
