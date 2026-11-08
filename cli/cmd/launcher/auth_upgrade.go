package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/authupgrade"
	"gitflic.ru/skif4er/launcher/cli/internal/dbmigrate"
)

// Операция handleAuthUpgrade02911 намеренно отделена от db migrate apply.
// Оператор промышленной среды должен явно согласовать внешнее резервное
// копирование PostgreSQL и контролируемое окно обслуживания без записи.
// Проверка сумм миграций остаётся за существующим dbmigrate.
func handleAuthUpgrade02911(args []string) error {
	if len(args) == 0 {
		return errors.New("db auth-upgrade: требуется «preflight|apply|verify»")
	}
	action := args[0]
	if action != "preflight" && action != "apply" && action != "verify" {
		return fmt.Errorf("Неизвестное значение: команда обновления авторизации %q", action)
	}
	flags := flag.NewFlagSet("auth-upgrade "+action, flag.ContinueOnError)
	dsn := flags.String("dsn", os.Getenv("LAUNCHER_DATABASE_DSN"), "DSN PostgreSQL (используйте LAUNCHER_DATABASE_DSN)")
	psql := flags.String("psql", "psql", "Исполняемый файл psql")
	snapshot := flags.String("snapshot", "", "Путь к контрольной точке сохранности данных")
	backup := flags.Bool("backup-confirmed", false, "Оператор подтвердил резервную копию PostgreSQL, пригодную для независимого восстановления")
	maintenance := flags.Bool("maintenance-confirmed", false, "Оператор остановил запись авторизации, GameProfile и исходных данных Gravit")
	var allow providerIDs02911
	flags.Var(&allow, "allow-provider", "Явно подтверждённый идентификатор провайдера (можно повторять); не выполнять неявную миграцию сторонних провайдеров")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("Неожиданные аргументы команды")
	}
	if *snapshot == "" {
		return errors.New("Параметр --snapshot должен указывать на существующий или новый файл контрольной точки")
	}
	if action == "apply" && (!*backup || !*maintenance) {
		return errors.New("Для применения требуются --backup-confirmed и --maintenance-confirmed; Launcher не может автоматически создать или проверить резервную копию на внешнем узле")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if action == "preflight" {
		checkpoint, err := authupgrade.ScanPSQL(ctx, *psql, *dsn, allow)
		if err != nil {
			return err
		}
		if err := authupgrade.Save(*snapshot, checkpoint); err != nil {
			return err
		}
		printJSON(map[string]any{"status": "preflight-passed", "checkpoint": *snapshot, "counts": checkpoint.Identity, "providers": checkpoint.Providers, "passwordFormats": checkpoint.PasswordFormats, "note": "Контрольная точка содержит только отпечатки, количества и идентификаторы провайдеров. Перед применением остановите запись в исходные данные."})
		return nil
	}
	expected, err := authupgrade.Load(*snapshot)
	if err != nil {
		return err
	}
	current, err := authupgrade.ScanPSQL(ctx, *psql, *dsn, expected.AllowedProviders)
	if err != nil {
		return err
	}
	if err := authupgrade.Compare(expected, current); err != nil {
		return fmt.Errorf("Не удалось сохранить состояние перед обновлением: %w", err)
	}
	if action == "apply" {
		if _, err := dbmigrate.ApplyWithPSQL(ctx, *psql, *dsn); err != nil {
			return fmt.Errorf("Применение миграции завершилось ошибкой; при необходимости восстановите данные только из проверенной резервной копии: %w", err)
		}
	}
	if _, err := dbmigrate.VerifyWithPSQL(ctx, *psql, *dsn); err != nil {
		return fmt.Errorf("Контрольные суммы целевой миграции не проверены: %w", err)
	}
	post, err := authupgrade.ScanPSQL(ctx, *psql, *dsn, expected.AllowedProviders)
	if err != nil {
		return err
	}
	if err := authupgrade.Compare(expected, post); err != nil {
		return fmt.Errorf("После обновления изменена идентичность компонента: %w", err)
	}
	printJSON(map[string]any{"status": "verified", "action": action, "checkpoint": *snapshot, "identity": post.Identity, "migrations": "Зафиксировано и актуально", "message": "Изменений в принадлежности учётных записей и UUID не обнаружено. Возобновляйте трафик только после проверок внешнего провайдера и Minecraft."})
	return nil
}

type providerIDs02911 []string

func (p *providerIDs02911) String() string { return strings.Join(*p, ",") }
func (p *providerIDs02911) Set(v string) error {
	if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\x00") {
		return errors.New("Некорректный ID провайдера")
	}
	for _, existing := range *p {
		if existing == v {
			return errors.New("Параметр --allow-provider указан несколько раз")
		}
	}
	*p = append(*p, v)
	return nil
}
