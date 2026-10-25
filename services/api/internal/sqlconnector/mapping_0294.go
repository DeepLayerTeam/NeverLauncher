package sqlconnector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MappedColumn describes an actual, mapped DB column without returning any row
// content (especially password hashes). It is safe to expose as a diagnostics preview.
type MappedColumn struct {
	Field        string `json:"field"`
	Column       string `json:"column"`
	DatabaseType string `json:"databaseType,omitempty"`
}

// InspectMapping validates the live SQL source before accepting any logins.
// The query is read-only, fetches no rows and selects only explicitly mapped
// columns, so scoped DB credentials need not have SELECT * permission.
// Config must come from Normalize (identifiers have already been validated).
func InspectMapping(ctx context.Context, db *sql.DB, cfg RuntimeConfig) ([]MappedColumn, error) {
	if db == nil {
		return nil, errors.New("SQL mapping: database handle is nil")
	}
	if err := validateTableIdentifier(cfg.Table); err != nil {
		return nil, err
	}
	if err := validateColumns(cfg.Columns); err != nil {
		return nil, err
	}
	fields := []struct{ field, column string }{
		{"id", cfg.Columns.ID}, {"username", cfg.Columns.Username},
		{"email", cfg.Columns.Email}, {"password", cfg.Columns.Password},
		{"status", cfg.Columns.Status}, {"displayName", cfg.Columns.DisplayName},
		{"groups", cfg.Columns.Groups}, {"roles", cfg.Columns.Roles},
		{"minecraftUuid", cfg.Columns.MinecraftUUID},
	}
	marker := `"`
	if cfg.Driver == "mysql" || cfg.Driver == "mariadb" {
		marker = "`"
	}
	quote := func(name string) string {
		parts := strings.Split(name, ".")
		for i := range parts {
			parts[i] = marker + parts[i] + marker
		}
		return strings.Join(parts, ".")
	}
	var projection []string
	var selected []MappedColumn
	for _, f := range fields {
		if f.column == "" {
			continue
		}
		projection = append(projection, quote(f.column))
		selected = append(selected, MappedColumn{Field: f.field, Column: f.column})
	}
	inspectCtx, cancel := context.WithTimeout(ctx, cfg.QueryTimeoutDuration)
	defer cancel()
	tx, err := db.BeginTx(inspectCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("SQL schema inspection transaction: %w", err)
	}
	defer tx.Rollback()
	// Placeholder-free, entirely identifier-validated SQL: safe on all drivers.
	query := "SELECT " + strings.Join(projection, ", ") + " FROM " + quote(cfg.Table) + " WHERE 1 = 0"
	rows, err := tx.QueryContext(inspectCtx, query)
	if err != nil {
		return nil, fmt.Errorf("SQL schema mismatch or insufficient SELECT privilege: %w", err)
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		rows.Close()
		return nil, fmt.Errorf("SQL column type inspection: %w", err)
	}
	if len(types) != len(selected) {
		rows.Close()
		return nil, errors.New("SQL mapped column count mismatch")
	}
	for i, col := range types {
		selected[i].DatabaseType = strings.ToUpper(col.DatabaseTypeName())
		if selected[i].Field == "password" || selected[i].Field == "minecraftUuid" {
			// Binary digests require a dedicated explicit encoding; implicit
			// database CAST(blob AS text) differs between PG and MySQL.
			name := selected[i].DatabaseType
			if strings.Contains(name, "BINARY") || strings.Contains(name, "BLOB") || name == "BYTEA" || name == "VARBINARY" {
				rows.Close()
				return nil, fmt.Errorf("SQL %s column is binary; use an explicitly encoded text column", selected[i].Field)
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("SQL schema inspection rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("SQL schema inspection close: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("SQL schema inspection commit: %w", err)
	}
	return selected, nil
}
