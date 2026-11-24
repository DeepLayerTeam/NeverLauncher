//go:build !launcher_nopgx

package repository

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestAIGatewayPostgresCrossReplica121(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer a.db.Close()
	b := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	// An isolated historical month avoids touching the current-month ledger.
	now := time.Date(1998, 7, 15, 0, 0, 0, 0, time.UTC)
	month := now.Format("2006-01")
	// This test requires a disposable DB; never run against production.
	if _, err := a.db.ExecContext(ctx, `DELETE FROM ai_requests WHERE month=$1`, month); err != nil {
		t.Fatal(err)
	}
	defer a.db.ExecContext(context.Background(), `DELETE FROM ai_requests WHERE month=$1`, month)
	x, err := a.AILedger(ctx)
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.AILedger(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exerciseAILedger121(t, x, y, month, now.Unix())
}
