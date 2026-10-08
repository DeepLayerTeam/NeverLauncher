//go:build !neverlauncher_nopgx

package sqlconnector

import (
	"database/sql"
	"fmt"

	mysql "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func openDatabase(cfg RuntimeConfig) (*sql.DB, error) {
	switch cfg.Driver {
	case "postgresql":
		if err := validatePostgresTLS(cfg); err != nil {
			return nil, err
		}
		return sql.Open("pgx", cfg.DSN)
	case "mysql", "mariadb":
		mysqlCfg, err := mysql.ParseDSN(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("parse MySQL/MariaDB DSN: %w", err)
		}
		if err := validateMySQLTLS(cfg, mysqlCfg); err != nil {
			return nil, err
		}
		if mysqlCfg.Timeout == 0 {
			mysqlCfg.Timeout = cfg.ConnectTimeoutDuration
		}
		if mysqlCfg.ReadTimeout == 0 {
			mysqlCfg.ReadTimeout = cfg.QueryTimeoutDuration
		}
		if mysqlCfg.WriteTimeout == 0 {
			mysqlCfg.WriteTimeout = cfg.QueryTimeoutDuration
		}
		mysqlCfg.ParseTime = true
		return sql.Open("mysql", mysqlCfg.FormatDSN())
	default:
		return nil, fmt.Errorf("unsupported SQL driver %q", cfg.Driver)
	}
}

func validateMySQLTLS(cfg RuntimeConfig, parsed *mysql.Config) error {
	return validateMySQLTLSMode(cfg, parsed.TLSConfig)
}
