package sqlitepg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RejectUnapprovedBackend0475 prevents the API from silently activating an
// offline import. No HTTP/Coordinator state parity receipt exists in 0.47.5,
// so even a verified Core/file receipt is NOT a production cutover approval.
// This is evaluated before API bootstrap, workers and request listeners.
// Ordinary PostgreSQL installations with no SQLite import are unaffected.
func RejectUnapprovedBackend0475(ctx context.Context, dsn string) error {
	if strings.TrimSpace(dsn) == "" {
		return errors.New("PostgreSQL DSN required")
	}
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("PostgreSQL backend gate connection failed (credentials redacted): %w", err)
	}
	defer pg.Close(context.Background())
	for _, name := range []string{"public.sqlite_live_receipts_0473", Schema + ".migration_receipt"} {
		var present bool
		if err := pg.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&present); err != nil {
			return fmt.Errorf("cannot inspect cutover state: %w", err)
		}
		if !present {
			continue
		}
		var count int64
		// Identifiers are fixed by this source file, never interpolated from
		// an HTTP input or user-controlled PostgreSQL receipt.
		switch name {
		case "public.sqlite_live_receipts_0473":
			err = pg.QueryRow(ctx, `SELECT count(*) FROM public.sqlite_live_receipts_0473`).Scan(&count)
		default:
			err = pg.QueryRow(ctx, `SELECT count(*) FROM `+qualified("migration_receipt")).Scan(&count)
		}
		if err != nil {
			return fmt.Errorf("cannot inspect cutover receipts: %w", err)
		}
		if count != 0 {
			return errors.New("SQLite import present without verified HTTP/Coordinator cutover approval; refusing to start Backend (0.47.5)")
		}
	}
	return nil
}
