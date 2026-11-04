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

// Существующая команда только для карантина намеренно НЕ изменяется. Живой импорт
// выполняется явно, автономно и только в пустую полностью мигрированную БД
// SQLRepository. Неудачный живой этап оставляет staging без изменений, чтобы
// оператор исправил причину и безопасно повторил --from-staging.
func runPGLive0473(args []string) int {
	flags := flag.NewFlagSet("sqlite-to-postgres-live", flag.ContinueOnError)
	backup := flags.String("backup", "", "verified immutable SQLite Core backup and manifest")
	fromStaging := flags.Bool("from-staging", false, "reuse already verified immutable staging import")
	dsnEnv := flags.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "PostgreSQL DSN environment variable name")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall import deadline")
	mfaFile := flags.String("sqlite-mfa-key-file", "", "private 0600 SQLite Core 32-byte MFA key file")
	secretEnv := flags.String("postgres-secret-env", "", "environment variable holding the exact PostgreSQL HTTP API encryption secret")
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
		// Сохраняются исходная проверка, криптографические квитанции таблиц и
		// неизменяемая резервная копия источника. Разрушающая перезапись staging
		// запрещена.
		if _, err := sqlitepg.Import(ctx, *backup, dsn); err != nil {
			fmt.Fprintf(os.Stderr, "immutable staging failed; no SQLRepository changes: %v\n", err)
			return 1
		}
	}
	var keys sqlitepg.MFASecrets0474
	if *mfaFile != "" || *secretEnv != "" {
		if *mfaFile == "" || *secretEnv == "" || strings.ContainsAny(*secretEnv, "=\x00 \r\n\t") {
			fmt.Fprintln(os.Stderr, "both MFA key-file and PostgreSQL secret environment name are required")
			return 2
		}
		var err error
		keys.SQLiteMFAKey, err = readAuthKey(*mfaFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read private SQLite MFA key:", err)
			return 2
		}
		keys.PostgreSQLSecret = os.Getenv(*secretEnv)
		if keys.PostgreSQLSecret == "" {
			fmt.Fprintln(os.Stderr, "PostgreSQL API secret env is empty")
			return 2
		}
		defer func() {
			for i := range keys.SQLiteMFAKey {
				keys.SQLiteMFAKey[i] = 0
			}
		}()
	}
	report, err := sqlitepg.PopulateLiveWithMFA0474(ctx, dsn, keys)
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
