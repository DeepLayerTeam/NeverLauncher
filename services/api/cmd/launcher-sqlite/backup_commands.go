package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func isBackupAction(action string) bool {
	switch action {
	case "backup", "backup-verify", "restore", "pre-upgrade":
		return true
	}
	return false
}

func runBackupAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "SQLite database path")
	backup := flags.String("backup", "", "backup .db file path")
	replace := flags.Bool("replace", false, "explicitly replace existing offline database (old file kept for rollback)")
	timeout := flags.Duration("timeout", 3*time.Minute, "deadline for snapshot/check")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if len(flags.Args()) != 0 || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "invalid backup flags")
		return 2
	}
	if *backup == "" {
		fmt.Fprintln(os.Stderr, "--backup required")
		return 2
	}
	if (action == "backup" || action == "pre-upgrade" || action == "restore") && *db == "" {
		fmt.Fprintln(os.Stderr, "--db required")
		return 2
	}
	if *replace && action != "restore" {
		fmt.Fprintln(os.Stderr, "--replace only allowed with restore")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	output := map[string]any{"action": action}
	var err error
	switch action {
	case "backup":
		var m sqlitedurable.BackupManifest
		m, err = sqlitedurable.OnlineBackup(ctx, *db, *backup)
		if err == nil {
			output["backup"] = *backup
			output["manifest"] = m
		}
	case "backup-verify":
		var m sqlitedurable.BackupManifest
		m, err = sqlitedurable.VerifyBackup(ctx, *backup)
		if err == nil {
			output["manifest"] = m
		}
	case "restore":
		var old string
		old, err = sqlitedurable.RestoreBackup(ctx, *backup, *db, *replace)
		if err == nil {
			output["restoredTo"] = *db
			output["rollbackFile"] = old
		}
	case "pre-upgrade":
		// Предварительная проверка обновления должна включать полный путь
		// восстановления: копию, целостность SQLite, внешние ключи и семантические
		// инварианты репозитория.
		var m sqlitedurable.BackupManifest
		m, err = sqlitedurable.OnlineBackup(ctx, *db, *backup)
		if err == nil {
			_, err = sqlitedurable.VerifyBackup(ctx, *backup)
		}
		if err == nil {
			// Восстанавливайте в новый закрытый каталог на ТОЙ ЖЕ поддерживаемой
			// локальной файловой системе.
			base := filepath.Dir(*backup)
			dir, e := os.MkdirTemp(base, ".launcher-pre-upgrade-restore-*")
			if e != nil {
				err = e
			} else {
				defer os.RemoveAll(dir)
				// MkdirTemp всегда создаёт каталог с правами 0700. Никогда не использует
				// живую БД повторно.
				target := filepath.Join(dir, "restored.db")
				_, err = sqlitedurable.RestoreBackup(ctx, *backup, target, false)
				if err == nil {
					var r *sqlitecore.Repository
					r, err = sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: target})
					if err == nil {
						err = errors.Join(r.Check(ctx), r.Close())
					}
				}
			}
		}
		if err == nil {
			output["verifiedRestore"] = true
			output["backup"] = *backup
			output["manifest"] = m
			output["upgradeMayProceed"] = true
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sqlite "+action+" failed closed:", err)
		return 1
	}
	output["status"] = "ok"
	if e := json.NewEncoder(os.Stdout).Encode(output); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
