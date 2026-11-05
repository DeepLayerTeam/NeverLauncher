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

func runPGExport(args []string) int {
	flags := flag.NewFlagSet("postgres-to-sqlite", flag.ContinueOnError)
	target := flags.String("backup", "", "Путь к новой резервной копии SQLite (манифест .json будет создан)")
	env := flags.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Переменная окружения с DSN PostgreSQL")
	timeout := flags.Duration("timeout", 30*time.Minute, "deadline")
	acknowledge := flags.Bool("ack-no-backend-cutover", false, "Подтвердить, что экспорт создаёт проверенный автономный снимок, а не переключает рабочий Backend с PostgreSQL на SQLite")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *timeout <= 0 || !*acknowledge || flags.NArg() != 0 || *env == "" || strings.ContainsAny(*env, "=\x00 \n") {
		fmt.Fprintln(os.Stderr, "необходимы --backup, --ack-no-backend-cutover, положительный --timeout и корректный --dsn-env")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "Пустое значение: переменная окружения DSN PostgreSQL")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := sqlitepg.Export(ctx, dsn, *target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка проверенного экспорта PostgreSQL → SQLite: %v\n", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
