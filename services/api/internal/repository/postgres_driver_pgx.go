//Go:сборка!neverlauncher_nopgx
// +сборка!neverlauncher_nopgx

package repository

import _ "github.com/jackc/pgx/v5/stdlib"

// Этот файл регистрирует pgx database/sql драйвер для production-сборки Серверная часть API.
// Драйвер имя: pgx.
//
// Настройка по умолчанию:
//
// NEVERLAUNCHER_SQL_DRIVER=pgx
// NEVERLAUNCHER_REPOSITORY_DRIVER=PostgreSQL
