//go:build !launcher_nopgx
// +build !launcher_nopgx

package repository

import _ "github.com/jackc/pgx/v5/stdlib"

// Этот файл регистрирует pgx database/sql driver для production-сборки Backend API.
// Имя драйвера: pgx.
//
// Настройка по умолчанию:
//
//   LAUNCHER_SQL_DRIVER=pgx
//   LAUNCHER_REPOSITORY_DRIVER=postgres
