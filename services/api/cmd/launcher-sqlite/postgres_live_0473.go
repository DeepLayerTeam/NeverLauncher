package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitepg"
)

// This intentionally does NOT change the existing quarantine-only command.
// The live import is explicit, offline and only allowed on an empty, fully
// migrated SQLRepository database. A failed live phase leaves staging intact
// so the operator can repair the cause and retry --from-staging safely.
func runPGLive0473(args []string) int {
	flags := flag.NewFlagSet("sqlite-to-postgres-live", flag.ContinueOnError)
	backup := flags.String("backup", "", "verified immutable SQLite Core backup and manifest")
	fromStaging := flags.Bool("from-staging", false, "reuse already verified immutable staging import")
	dsnEnv := flags.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "PostgreSQL DSN environment variable name")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall import deadline")
	ack := flags.Bool("ack-live-import", false, "acknowledge offline writes into EMPTY SQLRepository database")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*ack || *timeout <= 0 || flags.NArg() != 0 || (*fromStaging == (*backup != "")) {
		fmt.Fprintln(os.Stderr, "required: --ack-live-import and exactly one of --backup PATH or --from-staging, with positive --timeout")
		return 2
	}
	if *dsnEnv == "" || strings.ContainsAny(*dsnEnv, "=\x00 \r\n\t") {
		fmt.Fprintln(os.Stderr, "invalid --dsn-env")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PostgreSQL DSN env is empty")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if !*fromStaging {
		// Keeps the original verification, cryptographic table receipts, and
		// immutable source backup. No destructive staging overwrite allowed.
		if _, err := sqlitepg.Import(ctx, *backup, dsn); err != nil {
			fmt.Fprintf(os.Stderr, "immutable staging failed; no SQLRepository changes: %v\n", err)
			return 1
		}
	}
	report, err := sqlitepg.PopulateLive0473(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SQLRepository live import failed/rolled back; existing staging retained (commit errors require reconciliation): %v\n", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
