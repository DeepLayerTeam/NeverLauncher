//go:build launcher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	return nil, fmt.Errorf("Драйверы SQL-базы авторизации исключены тегом сборки launcher_nopgx")
}
