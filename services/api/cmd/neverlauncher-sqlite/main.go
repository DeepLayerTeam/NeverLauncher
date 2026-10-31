// launcher-sqlite is the DEP00 physical SQLite WAL preflight/verification
// executable. It is intentionally NOT a substitute for the future DEP01 app
// schema or DEP03 Redis-less coordinator.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"os"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) > 0 && (args[0] == "minimal-to-postgres" || args[0] == "postgres-to-minimal") {
		return runMinimalPG0377(args[0], args[1:])
	}
	if len(args) > 0 && args[0] == "postgres-to-sqlite" {
		return runPGExport(args[1:])
	}
	if len(args) > 0 && args[0] == "sqlite-to-postgres" {
		return runPGTransfer(args[1:])
	}
	if len(args) > 0 && isBackupAction(args[0]) {
		return runBackupAction(args)
	}
	if len(args) > 0 && isFullStateAction(args[0]) {
		return runFullStateAction(args)
	}
	if len(args) > 0 && isDurableAction(args[0]) {
		return runDurableAction(args)
	}
	if len(args) > 0 && isJoinAction(args[0]) {
		return runJoinAction(args)
	}
	if len(args) > 0 && isAuthAction(args[0]) {
		return runAuthAction(args)
	}
	if len(args) > 0 && isCoreAction(args[0]) {
		return runCoreAction(args)
	}
	if len(args) == 0 || (args[0] != "verify" && args[0] != "probe" && args[0] != "core-init" && args[0] != "core-status") {
		fmt.Fprintln(os.Stderr, "usage: launcher-sqlite {verify|probe|core-init|core-status|backup|backup-verify|restore|pre-upgrade} [--db PATH] [--backup PATH]")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("db", "", "absolute or relative on-disk database pathname")
	timeout := flags.Duration("timeout", 15*time.Second, "overall operation deadline")
	readers := flags.Int("readers", 4, "maximum concurrent SQLite read connections (1..16)")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "--db and positive --timeout are required; no positional args")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	opts := sqlitedurable.Options{Path: *path, Readers: *readers}
	payload := map[string]any{"component": "sqlite-storage", "platform": sqlitedurable.Platform(), "driver": sqlitedurable.DriverVersion, "sqliteEngine": sqlitedurable.EngineVersion, "operation": args[0]}
	var err error
	if args[0] == "core-init" || args[0] == "core-status" {
		var repo *sqlitecore.Repository
		if args[0] == "core-init" {
			repo, err = sqlitecore.Open(ctx, opts)
		} else {
			// core-status must never create a previously nonexistent file.
			if _, statErr := os.Stat(*path); statErr != nil {
				err = statErr
			} else {
				repo, err = sqlitecore.OpenExisting(ctx, opts)
			}
		}
		if err == nil {
			var counts map[string]int64
			counts, err = repo.Count(ctx)
			if err == nil {
				payload["schemaVersion"] = sqlitecore.SchemaVersion
				payload["counts"] = counts
			}
			closeErr := repo.Close()
			if err == nil {
				err = closeErr
			}
		}
	} else if args[0] == "probe" {
		var status sqlitedurable.WALStatus
		status, err = sqlitedurable.ProbeDurability(ctx, opts)
		if err == nil {
			payload["wal"] = status
			payload["durableCommitReopen"] = true
		}
	} else {
		var s *sqlitedurable.Store
		s, err = sqlitedurable.Open(ctx, opts)
		if err == nil {
			var status sqlitedurable.WALStatus
			status, err = s.Checkpoint(ctx)
			payload["wal"] = status
			errClose := s.Close()
			if err == nil {
				err = errClose
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite storage failed closed: %v\n", err)
		return 1
	}
	payload["status"] = "ok"
	if e := json.NewEncoder(os.Stdout).Encode(payload); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
