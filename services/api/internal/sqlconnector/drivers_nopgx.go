//go:build launcher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	return nil, fmt.Errorf("SQL auth database drivers are excluded by launcher_nopgx build tag")
}
