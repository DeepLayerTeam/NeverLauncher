//go:build !neverlauncher_nopgx
// +build !neverlauncher_nopgx

package repository

import _ "github.com/jackc/pgx/v5/stdlib"

// Этот файл регистрирует pgx database/sql driver для production-сборки Backend API.
// Driver name: pgx.
//
// Настройка по умолчанию:
//
//   NEVERLAUNCHER_SQL_DRIVER=pgx
//   NEVERLAUNCHER_REPOSITORY_DRIVER=postgres
