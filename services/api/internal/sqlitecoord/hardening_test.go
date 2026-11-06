package sqlitecoord

import (
	"context"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"strings"
	"testing"
)

func TestCoordinator0471SchemaDriftFailClosed(t *testing.T) {
	ctx := context.Background()
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `DROP INDEX coord_limits_expiry`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if next, err := Open(ctx, path); err == nil {
		_ = next.Close()
		t.Fatal("partial coordinator schema silently rebuilt")
	} else if !strings.Contains(err.Error(), "partial schema") {
		t.Fatalf("Неожиданная ошибка схемы: %v", err)
	}
}

func TestCoordinator0471RejectsForeignSchema(t *testing.T) {
	ctx := context.Background()
	path := coordTestPath(t)
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		if isUnsupportedFS(err) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, `CREATE TABLE coord_meta (key TEXT PRIMARY KEY, value TEXT)`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := Open(ctx, path); err == nil {
		_ = c.Close()
		t.Fatal("incompatible schema accepted")
	}
}
