//go:build launcher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	return nil, fmt.Errorf("Драйверы SQL для базы авторизации исключены флагом сборки launcher_nopgx")
}
