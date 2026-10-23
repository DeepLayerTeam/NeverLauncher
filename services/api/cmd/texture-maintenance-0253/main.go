// texture-maintenance-0253 runs offline, operator-invoked backup, restore, and
// GC against the same local/S3 store configured for the API. It exposes no HTTP.
package main

import (
	"context"
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
	command := flag.String("command", "", "backup|restore|gc")
	backup := flag.String("backup", "", "immutable snapshot directory (required for backup/restore)")
	limit := flag.Int("limit", 100, "GC batch size 1..100")
	flag.Parse()
	if *command != "backup" && *command != "restore" && *command != "gc" {
		return errors.New("--command must be backup, restore or gc")
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
	case "backup", "restore":
		rows, err := repo.TextureBackupRows0253(ctx, driver)
		if err != nil {
			return err
		}
		objects := make([]storage.TextureBackupObject0253, 0, len(rows))
		for _, r := range rows {
			objects = append(objects, storage.TextureBackupObject0253{Digest: r.Digest, ByteSize: r.ByteSize, Driver: r.Driver, ObjectKey: r.ObjectKey})
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
		candidates, err := repo.ClaimTextureGarbage0253(ctx, driver, *limit)
		if err != nil {
			return err
		}
		for _, candidate := range candidates {
			// Validate object metadata before destructive operations.
			if candidate.Driver != driver || candidate.ObjectKey != "texture-blobs/sha256/"+candidate.Digest[:2]+"/"+candidate.Digest+".png" {
				return errors.New("invalid GC object key")
			}
			if err := storage.DeleteTexture0253(ctx, store, candidate.Digest); err != nil {
				_ = repo.ReleaseTextureGarbage0253(ctx, candidate.Digest)
				return fmt.Errorf("GC %s: %w", candidate.Digest, err)
			}
			if err := repo.FinishTextureGarbage0253(ctx, candidate.Digest); err != nil {
				return err
			}
		}
		fmt.Printf("deleted %d unreferenced texture objects\n", len(candidates))
	}
	return nil
}
