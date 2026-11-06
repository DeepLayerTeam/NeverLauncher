package sqlitedurable

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLite0471RejectsSymlinkedWAL(t *testing.T) {
	opt := testOptions(t)
	other := filepath.Join(filepath.Dir(opt.Path), "outside")
	if err := os.WriteFile(other, []byte("not a wal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, opt.Path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), opt); err == nil {
		_ = store.Close()
		t.Fatal("Ошибочно принят файл WAL SQLite через символическую ссылку")
	} else if !strings.Contains(err.Error(), "sidecar") {
		t.Fatal(err)
	}
}

func TestSQLite0471TruncatingCheckpoint(t *testing.T) {
	opt := testOptions(t)
	s, err := Open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err = s.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, `CREATE TABLE events(id TEXT PRIMARY KEY)`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, `INSERT INTO events(id) VALUES ('acknowledged')`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	status, err := s.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Сбой контрольной точки %+v: %v", status, err)
	}
	if status.Busy != 0 {
		t.Fatalf("Операция не завершена: %+v", status)
	}
	if err := s.Read(ctx, func(q Executor) error {
		var n int
		e := q.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE id='acknowledged'`).Scan(&n)
		if e == nil && n != 1 {
			return fmt.Errorf("зафиксированное событие WAL потеряно: %d", n)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}
