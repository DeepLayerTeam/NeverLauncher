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
	backup := flags.String("backup", "", "Проверенная неизменяемая резервная копия SQLite Core и её манифест")
	fromStaging := flags.Bool("from-staging", false, "Повторно использовать ранее проверенный неизменяемый промежуточный импорт")
	dsnEnv := flags.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Имя переменной окружения с DSN PostgreSQL")
	timeout := flags.Duration("timeout", 30*time.Minute, "Общий предельный срок импорта")
	mfaFile := flags.String("sqlite-mfa-key-file", "", "Приватный файл с 32-байтовым ключом MFA для SQLite Core (права 0600)")
	secretEnv := flags.String("postgres-secret-env", "", "Переменная окружения с точным секретом шифрования HTTP API PostgreSQL")
	ack := flags.Bool("ack-live-import", false, "Подтвердить автономную запись в ПУСТУЮ базу данных SQLRepository")
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
		fmt.Fprintln(os.Stderr, "Пустое значение: переменная окружения с DSN PostgreSQL")
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
			fmt.Fprintln(os.Stderr, "Требуется: «both MFA key-file and PostgreSQL secret environment name are»")
			return 2
		}
		var err error
		keys.SQLiteMFAKey, err = readAuthKey(*mfaFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Не удалось прочитать «private SQLite MFA key:»", err)
			return 2
		}
		keys.PostgreSQLSecret = os.Getenv(*secretEnv)
		if keys.PostgreSQLSecret == "" {
			fmt.Fprintln(os.Stderr, "Пустое значение: «PostgreSQL API secret env»")
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
