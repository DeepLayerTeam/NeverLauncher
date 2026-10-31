//go:build launcher_nopgx
// +build launcher_nopgx

package repository

// Автономные тестовые сборки в песочнице используют тег launcher_nopgx, чтобы не
// загружать github.com/jackc/pgx/v5 при недоступном кеше модулей Go. В производственной
// сборке этот тег отсутствует, чтобы postgres_driver_pgx.go регистрировал драйвер pgx.
