package sqlitecoord

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func TestCoordinatorUpgrade0472PreservesLeasesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "coordinator.sqlite")
	store, err := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, s := range strings.Split(schema, ";\n") {
			if strings.TrimSpace(s) == "" {
				continue
			}
			if _, e := q.ExecContext(ctx, s); e != nil {
				return e
			}
		}
		for _, stmt := range []string{"DROP TABLE coord_lease_tokens", "DROP INDEX coord_channels_expiry", "DROP INDEX coord_leases_expiry", "DROP INDEX coord_limits_expiry"} {
			if _, e := q.ExecContext(ctx, stmt); e != nil {
				return e
			}
		}
		if _, e := q.ExecContext(ctx, "INSERT INTO coord_meta(key,value) VALUES('version',0)"); e != nil {
			return e
		}
		if _, e := q.ExecContext(ctx, `INSERT INTO coord_channels VALUES ('server','runtime','channel','replica','addr',42,0)`); e != nil {
			return e
		}
		if _, e := q.ExecContext(ctx, `INSERT INTO coord_leases VALUES ('server','cmd',?,?,7,0)`, digest("owner"), digest("old-token")); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, `INSERT INTO coord_limits VALUES (?,3,100,90)`, digest("rate"))
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var channel, lease, token, rate int
	err = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		for _, item := range []struct {
			query string
			into  *int
		}{
			{"SELECT count(*) FROM coord_channels WHERE resume_after=42", &channel},
			{"SELECT count(*) FROM coord_leases WHERE fence=7", &lease},
			{"SELECT count(*) FROM coord_lease_tokens WHERE token_hash='" + digest("old-token") + "' AND fence=7", &token},
			{"SELECT count(*) FROM coord_limits WHERE count=3", &rate},
		} {
			if e := q.QueryRowContext(ctx, item.query).Scan(item.into); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if channel != 1 || lease != 1 || token != 1 || rate != 1 {
		t.Fatalf("потеряны строки: %d %d %d %d", channel, lease, token, rate)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup %v %v", backups, err)
	}
	if _, err = sqlitedurable.VerifyBackup(ctx, backups[0]); err != nil {
		t.Fatal(err)
	}
	c, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	more, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "pre-upgrade-backups", "*.sqlite"))
	if len(more) != 1 {
		t.Fatal("миграция была выполнена повторно")
	}
	if _, err = os.Stat(backups[0] + ".json"); err != nil {
		t.Fatal(err)
	}
}
