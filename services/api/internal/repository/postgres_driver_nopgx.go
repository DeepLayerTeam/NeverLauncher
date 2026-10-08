//Go:сборка neverlauncher_nopgx
// +сборка neverlauncher_nopgx

package repository

// Offline/sandbox smoke собирает использовать neverlauncher_nopgx тег к avoid загрузка
// github.com/jackc/pgx/v5 когда Go модуль кэш является недоступный.
// Рабочий собирает должен omit этот тег так PostgreSQL_драйвер_pgx.Go регистрирует pgx драйвер.
