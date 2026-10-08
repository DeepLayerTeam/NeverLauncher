//go:build neverlauncher_nopgx
// +build neverlauncher_nopgx

package repository

// Offline/sandbox smoke builds use the neverlauncher_nopgx tag to avoid downloading
// github.com/jackc/pgx/v5 when the Go module cache is unavailable.
// Production builds must omit this tag so postgres_driver_pgx.go registers the pgx driver.
