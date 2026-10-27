package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitepg"
)

func runPGTransfer(args []string) int {
	flags := flag.NewFlagSet("sqlite-to-postgres", flag.ContinueOnError)
	backup := flags.String("backup", "", "path to an existing verified SQLite online backup with .json manifest")
	dsnEnv := flags.String("dsn-env", "NEVERLAUNCHER_POSTGRES_DSN", "name of environment variable containing PostgreSQL DSN")
	timeout := flags.Duration("timeout", 30*time.Minute, "operation deadline")
	acknowledge := flags.Bool("ack-staging-only", false, "acknowledge data is imported into a quarantine schema, not live Backend")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *backup == "" || *timeout <= 0 || flags.NArg() != 0 || !*acknowledge {
		fmt.Fprintln(os.Stderr, "--backup, --ack-staging-only and positive --timeout are required")
		return 2
	}
	if *dsnEnv == "" || strings.ContainsAny(*dsnEnv, "=\x00 \n") {
		fmt.Fprintln(os.Stderr, "invalid --dsn-env")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PostgreSQL DSN environment variable is empty")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := sqlitepg.Import(ctx, *backup, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SQLite -> PostgreSQL staging transfer failed; transaction rolled back or commit must be reconciled: %v\n", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
