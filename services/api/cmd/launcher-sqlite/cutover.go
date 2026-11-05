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

// Строгая автономная приёмочная проверка только на чтение. Она никогда не
// превращает квитанцию staging в разрешение запустить промышленный PostgreSQL
// Backend.
func runPGCutoverCheck0475(args []string) int {
	fs := flag.NewFlagSet("sqlite-to-postgres-cutover-check", flag.ContinueOnError)
	sha := fs.String("source-sha256", "", "SHA-256 проверенной резервной копии SQLite Core")
	project := fs.String("project", "", "Идентификатор перенесённого проекта")
	email := fs.String("owner-email", "", "Адрес электронной почты прежнего владельца")
	dsnEnv := fs.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Переменная окружения с DSN целевой базы PostgreSQL")
	timeout := fs.Duration("timeout", time.Minute, "Тайм-аут проверки только на чтение")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 || *timeout <= 0 || *sha == "" || *project == "" || *email == "" || *dsnEnv == "" || strings.ContainsAny(*dsnEnv, "= \t\n\r\x00") {
		fmt.Fprintln(os.Stderr, "Некорректное значение: «cutover check flags»")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "Пустое значение: переменная окружения с DSN PostgreSQL")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := sqlitepg.VerifyCutover0475(ctx, dsn, *sha, *project, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Проверка переключения завершилась безопасным отказом: %v\n", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
