package sqlconnector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MappedColumn описывает реальную сопоставленную колонку БД без возврата содержимого строк,
// особенно хешей паролей. Её безопасно показывать в диагностическом предпросмотре.
type MappedColumn struct {
	Field        string `json:"field"`
	Column       string `json:"column"`
	DatabaseType string `json:"databaseType,omitempty"`
}

// InspectMapping проверяет действующий SQL-источник до допуска входов. Запрос
// только для чтения, не получает строки и выбирает лишь явно сопоставленные
// колонки; поэтому ограниченным учётным данным БД не требуется SELECT *.
// Конфигурация должна поступать из Normalize после проверки идентификаторов.
func InspectMapping(ctx context.Context, db *sql.DB, cfg RuntimeConfig) ([]MappedColumn, error) {
	if db == nil {
		return nil, errors.New("SQL-сопоставление: дескриптор БД отсутствует")
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
		return nil, fmt.Errorf("Ошибка транзакции проверки схемы SQL: %w", err)
	}
	defer tx.Rollback()
	// SQL без плейсхолдеров, с полностью проверенными идентификаторами: безопасен
	// для всех драйверов.
	query := "SELECT " + strings.Join(projection, ", ") + " FROM " + quote(cfg.Table) + " WHERE 1 = 0"
	rows, err := tx.QueryContext(inspectCtx, query)
	if err != nil {
		return nil, fmt.Errorf("Несовпадение схемы SQL или недостаточно прав SELECT: %w", err)
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		rows.Close()
		return nil, fmt.Errorf("Ошибка проверки типа столбца SQL: %w", err)
	}
	if len(types) != len(selected) {
		rows.Close()
		return nil, errors.New("Несовпадение: число сопоставленных столбцов SQL")
	}
	for i, col := range types {
		selected[i].DatabaseType = strings.ToUpper(col.DatabaseTypeName())
		if selected[i].Field == "password" || selected[i].Field == "minecraftUuid" {
			// Двоичные хеши требуют отдельного явного кодирования; неявный CAST(blob AS
			// text) БД отличается в PG и MySQL.
			name := selected[i].DatabaseType
			if strings.Contains(name, "BINARY") || strings.Contains(name, "BLOB") || name == "BYTEA" || name == "VARBINARY" {
				rows.Close()
				return nil, fmt.Errorf("Столбец SQL %s двоичный; используйте текстовый столбец с явной кодировкой", selected[i].Field)
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("Ошибка чтения строк при проверке схемы SQL: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("Ошибка завершения проверки схемы SQL: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("Ошибка фиксации проверки схемы SQL: %w", err)
	}
	return selected, nil
}
