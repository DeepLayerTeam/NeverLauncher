// texture-maintenance-0253 runs offline, operator-invoked backup, restore, and
// GC against the same local/S3 store configured for the API. It exposes no HTTP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "texture-maintenance:", err)
		os.Exit(1)
	}
}
func run() error {
	command := flag.String("command", "", "backup|restore|gc|verify")
	backup := flag.String("backup", "", "immutable snapshot directory (required for backup/restore)")
	limit := flag.Int("limit", 100, "GC batch size 1..100")
	report := flag.String("report", "", "JSON report file for verify (must not exist)")
	flag.Parse()
	if *command != "backup" && *command != "restore" && *command != "gc" && *command != "verify" {
		return errors.New("--command must be backup, restore, gc or verify")
	}
	if (*command == "backup" || *command == "restore") && *backup == "" {
		return errors.New("--backup directory required")
	}
	dsn := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_DATABASE_DSN"))
	if dsn == "" {
		return errors.New("NEVERLAUNCHER_DATABASE_DSN required")
	}
	driver := env("NEVERLAUNCHER_STORAGE_DRIVER", "local")
	var store storage.Storage
	switch driver {
	case "local":
		store = storage.NewLocalStorage(env("NEVERLAUNCHER_STORAGE_LOCAL_PATH", "./data/storage"))
	case "s3":
		pathStyle, _ := strconv.ParseBool(env("NEVERLAUNCHER_STORAGE_S3_PATH_STYLE", "true"))
		s, err := storage.NewS3Storage(storage.S3Config{Endpoint: os.Getenv("NEVERLAUNCHER_STORAGE_S3_ENDPOINT"), Bucket: os.Getenv("NEVERLAUNCHER_STORAGE_S3_BUCKET"), Region: os.Getenv("NEVERLAUNCHER_STORAGE_S3_REGION"), AccessKey: os.Getenv("NEVERLAUNCHER_STORAGE_S3_ACCESS_KEY"), SecretKey: os.Getenv("NEVERLAUNCHER_STORAGE_S3_SECRET_KEY"), PathStyle: pathStyle})
		if err != nil {
			return err
		}
		store = s
	default:
		return fmt.Errorf("invalid storage driver %q", driver)
	}
	repo := repository.NewSQLRepository("pgx", dsn, "").(*repository.SQLRepository)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := store.Health(ctx); err != nil {
		return err
	}
	switch *command {
	case "backup", "restore", "verify":
		if _, err := repo.PruneTextureSnapshotPins02511(ctx); err != nil {
			return err
		}
		token, rows, err := repo.BeginTextureSnapshot02511(ctx, driver)
		if err != nil {
			return err
		}
		defer func() {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = repo.EndTextureSnapshot02511(cleanCtx, token)
		}()
		objects := make([]storage.TextureBackupObject0253, 0, len(rows))
		for _, r := range rows {
			objects = append(objects, storage.TextureBackupObject0253{Digest: r.Digest, ByteSize: r.ByteSize, Driver: r.Driver, ObjectKey: r.ObjectKey})
		}
		if *command == "verify" {
			checks := make([]storage.TextureVerification02511, 0, len(objects))
			bad := 0
			for _, obj := range objects {
				result := storage.VerifyTextureGA0260(ctx, store, obj)
				checks = append(checks, result)
				if result.Result != "ok" {
					bad++
				}
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			doc := struct {
				Driver  string                             `json:"driver"`
				Checked int                                `json:"checked"`
				Failed  int                                `json:"failed"`
				Objects []storage.TextureVerification02511 `json:"objects"`
			}{driver, len(objects), bad, checks}
			if *report != "" {
				file, err := os.OpenFile(*report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return err
				}
				encErr := json.NewEncoder(file).Encode(doc)
				syncErr := file.Sync()
				closeErr := file.Close()
				if encErr != nil {
					return encErr
				}
				if syncErr != nil {
					return syncErr
				}
				if closeErr != nil {
					return closeErr
				}
			} else if err := json.NewEncoder(os.Stdout).Encode(doc); err != nil {
				return err
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d texture objects failed integrity verification", bad, len(objects))
			}
			return nil
		}
		if *command == "backup" {
			if err := storage.BackupTextures0253(ctx, store, objects, *backup); err != nil {
				return err
			}
			fmt.Printf("backed up %d verified texture objects to %s\n", len(objects), *backup)
			return nil
		}
		n, err := storage.RestoreTextures0253(ctx, store, *backup, objects)
		if err != nil {
			return err
		}
		fmt.Printf("restored %d texture objects\n", n)
	case "gc":
		if _, err := repo.PruneTextureSnapshotPins02511(ctx); err != nil {
			return err
		}
		candidates, err := repo.ClaimTextureGarbage02511(ctx, driver, *limit)
		if err != nil {
			return err
		}
		// Aborted batches must not strand other claimed rows until lease expiry.
		// Successful rows are already deleted, so their release is a no-op.
		defer func() {
			cleanCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			for _, candidate := range candidates {
				_ = repo.ReleaseTextureGC02511(cleanCtx, candidate)
			}
		}()
		for _, candidate := range candidates {
			// Validate object metadata before destructive operations.
			if len(candidate.Digest) != 64 || candidate.Driver != driver || candidate.ObjectKey != "texture-blobs/sha256/"+candidate.Digest[:2]+"/"+candidate.Digest+".png" {
				return errors.New("invalid GC object key")
			}
			if err := repo.DeleteTextureWithLease02512(ctx, candidate, func(ctx context.Context, digest string) error {
				return storage.DeleteTextureSafely02511(ctx, store, digest)
			}); err != nil {
				return fmt.Errorf("GC %s: %w", candidate.Digest, err)
			}
		}
		fmt.Printf("deleted %d unreferenced texture objects\n", len(candidates))
	}
	return nil
}
