package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitepg"
	"os"
	"strings"
	"time"
)

func runMinimalPG0377(command string, args []string) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	bundle := flags.String("bundle", "", "Существующий автономный пакет резервной копии (импорт) или каталог для нового пакета (экспорт)")
	env := flags.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "Переменная окружения с DSN PostgreSQL")
	timeout := flags.Duration("timeout", 2*time.Hour, "Предельное время миграции")
	acknowledge := flags.Bool("ack-no-backend-cutover", false, "Подтвердить, что это проверенный автономный перенос данных, а не переключение рабочего Backend на PostgreSQL")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *bundle == "" || !*acknowledge || *timeout <= 0 || *env == "" || strings.ContainsAny(*env, "=\x00 \n") || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--bundle, --ack-no-backend-cutover, positive --timeout and valid --dsn-env are required")
		return 2
	}
	dsn := os.Getenv(*env)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "Пустое значение: переменная окружения DSN PostgreSQL")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var report sqlitepg.MinimalBundleReport0377
	var err error
	if command == "minimal-to-postgres" {
		report, err = sqlitepg.ImportMinimalBundle0377(ctx, *bundle, dsn)
	} else {
		report, err = sqlitepg.ExportMinimalBundle0377(ctx, dsn, *bundle)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Минимальный перенос завершился безопасным отказом: %v\n", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
