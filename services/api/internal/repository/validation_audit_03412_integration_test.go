//go:build !launcher_nopgx

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestV12SQLAuditImmutableAndNoManualCertification03412(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	pkg := fmt.Sprintf("v12-03412-%d", time.Now().UnixNano())
	if err := r.SaveValidationAttempt03412(ctx, validationEventFixture03412(pkg)); err != nil {
		t.Fatal(err)
	}
	rows, err := r.ListValidationAttempts03412(ctx, pkg, 0, 100)
	if err != nil || len(rows) != 1 || rows[0].Outcome != "rejected" || rows[0].ReasonCode != "untrusted-signature" {
		t.Fatalf("missing persisted rejection: %+v %v", rows, err)
	}
	for _, q := range []string{
		`UPDATE validation_attempt_events_03412 SET outcome='eligible' WHERE package_id=$1`,
		`DELETE FROM validation_attempt_events_03412 WHERE package_id=$1`,
	} {
		if _, err := r.db.ExecContext(ctx, q, pkg); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("SQL audit mutation succeeded: %s: %v", q, err)
		}
	}
	// No manual certification column or authority is created by V12 migration.
	var manual bool
	err = r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='validation_attempt_events_03412' AND column_name='certified')`).Scan(&manual)
	if err != nil || manual {
		t.Fatalf("manual certification column exists: %v", err)
	}
}

func validationEventFixture03412(pkg string) model.ValidationAttempt03412 {
	return model.ValidationAttempt03412{PackageID: pkg, Kind: "attestation", Outcome: "rejected", ReasonCode: "untrusted-signature", PayloadSHA256: strings.Repeat("f", 64)}
}
