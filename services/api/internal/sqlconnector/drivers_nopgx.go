//Go:сборка neverlauncher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	return nil, fmt.Errorf("SQL аутентификация база данных драйвер являются excluded через neverlauncher_nopgx сборка тег")
}
