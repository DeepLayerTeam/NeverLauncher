package sqlitecore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// До резервного копирования или применения DDL требуйте полное известное семейство
// предыдущей схемы; поддельного user_version чужой БД недостаточно.
func (r *Repository) preflightLegacy0472(ctx context.Context, version int) error {
	return r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		groups := [][]string{ddl}
		if version >= 323 {
			groups = append(groups, authDDL)
		}
		if version >= 324 {
			groups = append(groups, joinDDL)
		}
		if version >= 325 {
			groups = append(groups, durableDDL)
		}
		if version >= 326 {
			groups = append(groups, fullStateDDL)
		}
		for _, group := range groups {
			for _, statement := range group {
				words := strings.Fields(statement)
				if len(words) < 3 || !strings.EqualFold(words[0], "CREATE") || !strings.EqualFold(words[1], "TABLE") {
					continue
				}
				name := strings.Trim(words[2], "\"`[")
				if i := strings.IndexByte(name, '('); i >= 0 {
					name = name[:i]
				}
				var kind string
				err := q.QueryRowContext(ctx, `SELECT type FROM sqlite_master WHERE name=?`, name).Scan(&kind)
				if err != nil || kind != "table" {
					return fmt.Errorf("sqlite core legacy %d missing expected table %s: %v", version, name, err)
				}
			}
		}
		// Сохранённые ID, членство ролей и история профилей не должны незаметно
		// переназначаться миграцией по одному номеру версии.
		for table, cols := range map[string]map[string]string{
			"projects":          {"id": "TEXT", "name": "TEXT"},
			"profiles":          {"project_id": "TEXT", "id": "TEXT", "revision": "INTEGER", "digest": "TEXT"},
			"roles":             {"id": "TEXT", "permissions": "TEXT"},
			"users":             {"id": "TEXT", "email": "TEXT", "role_id": "TEXT", "password_hash": "TEXT"},
			"profile_revisions": {"project_id": "TEXT", "profile_id": "TEXT", "revision": "INTEGER", "spec": "TEXT"},
		} {
			rows, err := q.QueryContext(ctx, "PRAGMA table_info("+table+")")
			if err != nil {
				return err
			}
			found := make(map[string]string)
			for rows.Next() {
				var cid, notnull, pk int
				var name, typ string
				var def any
				if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
					break
				}
				found[name] = strings.ToUpper(typ)
			}
			err2 := rows.Err()
			closeErr := rows.Close()
			if err != nil {
				return err
			}
			if err2 != nil {
				return err2
			}
			if closeErr != nil {
				return closeErr
			}
			for name, typ := range cols {
				if found[name] != typ {
					return fmt.Errorf("sqlite core %d incompatible %s.%s: got %q", version, table, name, found[name])
				}
			}
		}
		return coreRecordPreflight0472(ctx, q)
	})
}

func hasCoreColumn0472(ctx context.Context, q sqlitedurable.Executor, table, column, typ string) (bool, error) {
	rows, err := q.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, t string
		var def any
		if err = rows.Scan(&cid, &name, &t, &notnull, &def, &pk); err != nil {
			break
		}
		if name == column {
			if strings.ToUpper(t) != typ {
				err = fmt.Errorf("Неожиданное значение: %s.%s тип %q", table, column, t)
				break
			}
			found = true
		}
	}
	if er := rows.Err(); err == nil {
		err = er
	}
	if er := rows.Close(); err == nil {
		err = er
	}
	return found, err
}

// Проверяйте доменные инварианты, существовавшие как до миграции, так и после.
// Некорректные старые строки должны останавливать обновление до любых изменений
// схемы.
func coreRecordPreflight0472(ctx context.Context, q sqlitedurable.Executor) error {
	checks := []string{
		`SELECT COUNT(*) FROM profiles p LEFT JOIN profile_revisions h ON h.project_id=p.project_id AND h.profile_id=p.id AND h.revision=p.revision AND h.digest=p.digest WHERE h.profile_id IS NULL`,
		`SELECT COUNT(*) FROM users u LEFT JOIN roles r ON r.id=u.role_id WHERE r.id IS NULL`,
		`SELECT COUNT(*) FROM project_user_roles pur LEFT JOIN roles r ON r.id=pur.role_id WHERE r.id IS NULL`,
		`SELECT COUNT(*) FROM roles WHERE NOT json_valid(permissions)`,
		`SELECT COUNT(*) FROM channel_heads h LEFT JOIN releases r ON r.id=h.release_id AND r.status='published' AND r.project_id=h.project_id AND r.profile_id=h.profile_id AND r.channel=h.channel WHERE r.id IS NULL`,
	}
	for _, stmt := range checks {
		var n int
		if err := q.QueryRowContext(ctx, stmt).Scan(&n); err != nil {
			return fmt.Errorf("sqlite core legacy records check: %w", err)
		}
		if n != 0 {
			return fmt.Errorf("sqlite core legacy records inconsistent (%d): %s", n, stmt)
		}
	}
	return nil
}

// Безопасно воспроизводите исторический шаг DDL после прерванного или частично
// отмеченного обновления: уже существующий объект принимается только при точном
// совпадении его SQL с архивной миграцией. Не используйте безусловно IF NOT
// EXISTS.
func applyCoreDDL0472(ctx context.Context, q sqlitedurable.Executor, stmt string) error {
	// Исторический authDDL содержит запрещённую коллизию пространства имён SQLite:
	// INDEX minecraft_sessions имеет имя TABLE minecraft_sessions. Сохраняйте
	// исторический текст DDL, но исполняйте его с исправленным именем индекса.
	if strings.HasPrefix(strings.TrimSpace(stmt), "CREATE INDEX minecraft_sessions ON minecraft_sessions(") {
		stmt = strings.Replace(stmt, "INDEX minecraft_sessions ON", "INDEX minecraft_sessions_session ON", 1)
	}
	words := strings.Fields(stmt)
	if len(words) < 3 || !strings.EqualFold(words[0], "CREATE") {
		return errors.New("unrecognized core migration DDL")
	}
	pos := 2
	if strings.EqualFold(words[1], "UNIQUE") {
		if len(words) < 4 || !strings.EqualFold(words[2], "INDEX") {
			return errors.New("unrecognized core unique DDL")
		}
		pos = 3
	} else if !strings.EqualFold(words[1], "TABLE") && !strings.EqualFold(words[1], "INDEX") && !strings.EqualFold(words[1], "TRIGGER") {
		return errors.New("unrecognized core migration object")
	}
	name := words[pos]
	var existing string
	err := q.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name=? AND type IN ('table','index','trigger')`, name).Scan(&existing)
	if err == nil {
		normalize := func(s string) string {
			return strings.ToLower(strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(s), ";")), ""))
		}
		if normalize(existing) != normalize(stmt) {
			return fmt.Errorf("sqlite core schema drift at %s", name)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = q.ExecContext(ctx, stmt)
	return err
}
