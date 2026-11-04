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
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// Run after sqlite-to-postgres-live against an OFFLINE destination. The source
// and target must be different stores and all service writers must be stopped.
func runPGFiles0474(args []string) int {
	fs := flag.NewFlagSet("sqlite-to-postgres-files", flag.ContinueOnError)
	sourceRoot := fs.String("source-root", "", "SQLite LocalStorage root")
	targetRoot := fs.String("target-root", "", "PostgreSQL LocalStorage root (omit for S3)")
	targetS3 := fs.Bool("target-s3", false, "write to an isolated S3 bucket configured by LAUNCHER_STORAGE_S3_* env")
	dsnEnv := fs.String("dsn-env", "LAUNCHER_POSTGRES_DSN", "environment variable containing target PostgreSQL DSN")
	timeout := fs.Duration("timeout", 4*time.Hour, "file copy deadline")
	offline := fs.Bool("ack-offline", false, "confirm both backends have stopped writing")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if !*offline || !*targetS3 && *targetRoot == "" || *targetS3 && *targetRoot != "" || *timeout <= 0 || *sourceRoot == "" || fs.NArg() != 0 || strings.TrimSpace(*dsnEnv) == "" || strings.ContainsAny(*dsnEnv, "= \t\r\n\x00") {
		fmt.Fprintln(os.Stderr, "requires --source-root, one of --target-root or --target-s3, --ack-offline, positive timeout")
		return 2
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PostgreSQL DSN environment variable is empty")
		return 2
	}
	src := storage.NewLocalStorage(*sourceRoot)
	var dst storage.Storage
	if *targetS3 {
		s3, e := storage.NewS3Storage(storage.S3Config{
			Endpoint: os.Getenv("LAUNCHER_STORAGE_S3_ENDPOINT"), Bucket: os.Getenv("LAUNCHER_STORAGE_S3_BUCKET"),
			Region: os.Getenv("LAUNCHER_STORAGE_S3_REGION"), AccessKey: os.Getenv("LAUNCHER_STORAGE_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("LAUNCHER_STORAGE_S3_SECRET_KEY"), PublicURL: os.Getenv("LAUNCHER_STORAGE_S3_PUBLIC_URL"),
			PathStyle: os.Getenv("LAUNCHER_STORAGE_S3_PATH_STYLE") != "false",
		})
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		dst = s3
	} else {
		dst = storage.NewLocalStorage(*targetRoot)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, e := sqlitepg.CopyFileObjects0474(ctx, dsn, src, dst)
	if e != nil {
		fmt.Fprintf(os.Stderr, "verified storage copy failed: %v\n", e)
		return 1
	}
	if e = json.NewEncoder(os.Stdout).Encode(report); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
