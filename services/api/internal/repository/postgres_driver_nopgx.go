//go:build neverlauncher_nopgx
// +build neverlauncher_nopgx

package repository

// Автономные тестовые сборки в песочнице используют тег neverlauncher_nopgx, чтобы не
// загружать github.com/jackc/pgx/v5 при недоступном кеше модулей Go. В производственной
// сборке этот тег отсутствует, чтобы postgres_driver_pgx.go регистрировал драйвер pgx.
