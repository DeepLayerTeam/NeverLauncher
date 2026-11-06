package sqlitecoord

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// Устаревший координатор v0 — исходная схема каналов, аренд и лимитов без
// tombstone-записей повторов и индексов срока. Исходные таблицы никогда не
// удаляются и не переписываются. Посторонняя, повреждённая или будущая схема
// отклоняется по умолчанию.
func coordinatorLegacy0472(ctx context.Context, q sqlitedurable.Executor) (bool, error) {
	expected := map[string]string{}
	for _, raw := range strings.Split(schema, ";\n") {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		fields := strings.Fields(stmt)
		if len(fields) < 6 {
			return false, fmt.Errorf("Некорректное значение: «DDL координатора» %q", stmt)
		}
		expected[fields[5]] = normalizeCoordinatorDDL0471(stmt)
	}
	rows, err := q.QueryContext(ctx, `SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','view','trigger')`)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for rows.Next() {
		var kind, name string
		var sqlText sql.NullString
		if err = rows.Scan(&kind, &name, &sqlText); err != nil {
			break
		}
		want, ok := expected[name]
		if !ok || !sqlText.Valid || normalizeCoordinatorDDL0471(sqlText.String) != want {
			err = fmt.Errorf("Координатор: несовместимый устаревший объект %s %s", kind, name)
			break
		}
		seen[name] = true
	}
	if er := rows.Err(); err == nil {
		err = er
	}
	if er := rows.Close(); err == nil {
		err = er
	}
	if err != nil {
		return false, err
	}
	if len(seen) == 0 {
		return false, nil
	} // fresh database
	for _, name := range []string{"coord_channels", "coord_leases", "coord_limits"} {
		if !seen[name] {
			return false, fmt.Errorf("В устаревшем координаторе отсутствует %s", name)
		}
	}
	version := 0
	if seen["coord_meta"] {
		err = q.QueryRowContext(ctx, "SELECT value FROM coord_meta WHERE key='version'").Scan(&version)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	if version != 0 && version != schemaVersion {
		return false, fmt.Errorf("Не поддерживается: «устаревшая схема координатора» %d", version)
	}
	if version == schemaVersion {
		// Частично созданная современная схема является повреждением, а не старым
		// релизом.
		_, err = validateExistingSchema0471(ctx, q)
		return false, err
	}
	return true, nil
}

func migrateCoordinatorLegacy0472(ctx context.Context, q sqlitedurable.Executor) error {
	legacy, err := coordinatorLegacy0472(ctx, q)
	if err != nil {
		return err
	}
	if !legacy {
		return errors.New("Обнаружено изменение: «состояние обновления устаревшей схемы координатора»")
	}
	for _, raw := range strings.Split(schema, ";\n") {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		if _, err = q.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("Ошибка устаревшей DDL-схемы координатора: %w", err)
		}
	}
	// Сохраняйте хеш токена действующей аренды и историю ограждений: обновление не
	// должно повторно выдавать ранее выданный токен аренды.
	if _, err = q.ExecContext(ctx, `INSERT OR IGNORE INTO coord_lease_tokens(server_id,command_id,token_hash,fence)
 SELECT server_id,command_id,token_hash,fence FROM coord_leases`); err != nil {
		return err
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO coord_meta(key,value) VALUES('version',1)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE coord_meta.value=0`); err != nil {
		return err
	}
	var v int
	if err = q.QueryRowContext(ctx, "SELECT value FROM coord_meta WHERE key='version'").Scan(&v); err != nil {
		return err
	}
	if v != schemaVersion {
		return fmt.Errorf("Версия миграции координатора %d", v)
	}
	_, err = validateExistingSchema0471(ctx, q)
	return err
}
