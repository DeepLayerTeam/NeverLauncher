//go:build neverlauncher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	return nil, fmt.Errorf("SQL auth database drivers are excluded by neverlauncher_nopgx build tag")
}
