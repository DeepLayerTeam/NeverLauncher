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

// handleAuthUpgrade02911 is deliberately separate from db migrate apply.
// A production operator must opt in with an off-host PostgreSQL backup and
// controlled write-free maintenance window. Database migration checksums stay
// enforced by the existing dbmigrate runner.
func handleAuthUpgrade02911(args []string) error {
	if len(args) == 0 {
		return errors.New("db auth-upgrade requires preflight|apply|verify")
	}
	action := args[0]
	if action != "preflight" && action != "apply" && action != "verify" {
		return fmt.Errorf("unknown auth-upgrade command %q", action)
	}
	flags := flag.NewFlagSet("auth-upgrade "+action, flag.ContinueOnError)
	dsn := flags.String("dsn", os.Getenv("NEVERLAUNCHER_DATABASE_DSN"), "PostgreSQL DSN (use NEVERLAUNCHER_DATABASE_DSN)")
	psql := flags.String("psql", "psql", "psql executable")
	snapshot := flags.String("snapshot", "", "path to preservation checkpoint")
	backup := flags.Bool("backup-confirmed", false, "operator verified an independently restorable PostgreSQL backup")
	maintenance := flags.Bool("maintenance-confirmed", false, "operator stopped authentication, GameProfile and Gravit source writes")
	var allow providerIDs02911
	flags.Var(&allow, "allow-provider", "explicitly verified provider ID (repeat); no implicit custom-provider migration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *snapshot == "" {
		return errors.New("--snapshot must name an existing or new checkpoint file")
	}
	if action == "apply" && (!*backup || !*maintenance) {
		return errors.New("apply requires --backup-confirmed and --maintenance-confirmed; Launcher cannot create or verify an off-host backup automatically")
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
		printJSON(map[string]any{"status": "preflight-passed", "checkpoint": *snapshot, "counts": checkpoint.Identity, "providers": checkpoint.Providers, "passwordFormats": checkpoint.PasswordFormats, "note": "Checkpoint contains fingerprints, counts and provider IDs only. Stop source writes before apply."})
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
		return fmt.Errorf("pre-upgrade preservation failure: %w", err)
	}
	if action == "apply" {
		if _, err := dbmigrate.ApplyWithPSQL(ctx, *psql, *dsn); err != nil {
			return fmt.Errorf("migration apply failed; restore only from verified backup if necessary: %w", err)
		}
	}
	if _, err := dbmigrate.VerifyWithPSQL(ctx, *psql, *dsn); err != nil {
		return fmt.Errorf("target migration checksums not verified: %w", err)
	}
	post, err := authupgrade.ScanPSQL(ctx, *psql, *dsn, expected.AllowedProviders)
	if err != nil {
		return err
	}
	if err := authupgrade.Compare(expected, post); err != nil {
		return fmt.Errorf("POST-UPGRADE IDENTITY DRIFT: %w", err)
	}
	printJSON(map[string]any{"status": "verified", "action": action, "checkpoint": *snapshot, "identity": post.Identity, "migrations": "sealed and current", "message": "No identity/UUID ownership drift detected. Re-enable traffic only after external-provider and Minecraft smoke tests."})
	return nil
}

type providerIDs02911 []string

func (p *providerIDs02911) String() string { return strings.Join(*p, ",") }
func (p *providerIDs02911) Set(v string) error {
	if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\x00") {
		return errors.New("invalid provider ID")
	}
	for _, existing := range *p {
		if existing == v {
			return errors.New("duplicate --allow-provider")
		}
	}
	*p = append(*p, v)
	return nil
}
