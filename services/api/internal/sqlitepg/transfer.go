// Пакет sqlitepg переносит неизменяемый проверенный снимок SQLite 326 в
// карантинную схему PostgreSQL. Он не изменяет действующие таблицы PostgreSQL и не
// разрешает небезопасное переключение серверной части. Сохраняются все таблицы, строки и столбцы,
// включая аудит, отозванные токены, билеты входа, UUID, бинарные данные и аренды.
package sqlitepg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"github.com/jackc/pgx/v5"
)

const Schema = "launcher_sqlite_import_03211"
const importVersion = "launcher-sqlite-to-postgresql-v2"
const batchSize = 256
const snapshotChunkSize = 256 * 1024

type TableResult struct {
	Name   string `json:"name"`
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}
type Report struct {
	Format                 string        `json:"format"`
	SnapshotSHA256         string        `json:"snapshotSha256"`
	SQLiteSchema           int           `json:"sqliteSchema"`
	PostgreSQLSchema       string        `json:"postgresqlSchema"`
	Tables                 []TableResult `json:"tables"`
	TotalRows              int64         `json:"totalRows"`
	ReadyForBackendCutover bool          `json:"readyForBackendCutover"`
}
type column struct {
	Name    string
	Type    string
	NotNull bool
	PK      int
}
type tableInfo struct {
	Name    string
	Columns []column
}

func identifier(name string) (string, error) {
	if name == "" || len(name) > 62 || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("Недопустимый SQL-идентификатор %q", name)
	}
	// Для VALUES не применяется интерполяция SQL. Идентификаторы всегда экранируются кавычками.
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`, nil
}
func quoted(name string) string     { s, _ := identifier(name); return s }
func qualified(table string) string { return quoted(Schema) + "." + quoted(table) }
func columnType(typ string) (string, error) {
	t := strings.ToUpper(strings.TrimSpace(typ))
	switch {
	case strings.Contains(t, "INT"):
		return "BIGINT", nil
	case strings.Contains(t, "BLOB") || t == "":
		return "BYTEA", nil
	case strings.Contains(t, "REAL") || strings.Contains(t, "FLOA") || strings.Contains(t, "DOUB"):
		return "DOUBLE PRECISION", nil
	case strings.Contains(t, "CHAR") || strings.Contains(t, "CLOB") || strings.Contains(t, "TEXT") || strings.Contains(t, "JSON") || strings.Contains(t, "DATE"):
		return "TEXT", nil
	default:
		return "", fmt.Errorf("Неподдерживаемый тип хранения столбца SQLite %q", typ)
	}
}
func columns(ctx context.Context, db *sql.DB, table string) ([]column, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_xinfo("+quoted(table)+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cs []column
	for rows.Next() {
		var cid, nn, pk, hidden int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &nn, &def, &pk, &hidden); err != nil {
			return nil, err
		}
		if hidden != 0 {
			return nil, fmt.Errorf("Таблица %s: вычисляемый или скрытый столбец SQLite не поддерживается", table)
		}
		if _, err = identifier(name); err != nil {
			return nil, err
		}
		if _, err = columnType(typ); err != nil {
			return nil, err
		}
		cs = append(cs, column{Name: name, Type: typ, NotNull: nn != 0, PK: pk})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, fmt.Errorf("Таблица %s не содержит столбцов", table)
	}
	return cs, nil
}
func tables(ctx context.Context, db *sql.DB) ([]tableInfo, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			break
		}
		names = append(names, n)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	var out []tableInfo
	for _, n := range names {
		if _, err = identifier(n); err != nil {
			return nil, err
		}
		cs, e := columns(ctx, db, n)
		if e != nil {
			return nil, e
		}
		out = append(out, tableInfo{Name: n, Columns: cs})
	}
	return out, nil
}
func requireCoreTables(ts []tableInfo) error {
	m := make(map[string]bool, len(ts))
	for _, t := range ts {
		m[t.Name] = true
	}
	for _, name := range []string{"projects", "profiles", "profile_revisions", "releases", "channel_heads", "users", "roles", "project_user_roles", "audit_events", "auth_sessions", "refresh_tokens", "refresh_families", "access_tokens", "mfa_totp", "mfa_recovery", "minecraft_profiles", "minecraft_sessions", "bridge_join_tickets", "bridge_nonces", "durable_jobs", "durable_job_attempts", "durable_scope_leases", "durable_outbox", "bridge_nodes", "extension_kv"} {
		if !m[name] {
			return fmt.Errorf("В схеме SQLite 326 отсутствует обязательная таблица постоянного хранения %q", name)
		}
	}
	return nil
}
func selectOrder(t tableInfo) string {
	pk := append([]column(nil), t.Columns...)
	sort.SliceStable(pk, func(i, j int) bool {
		if pk[i].PK == 0 {
			return false
		}
		if pk[j].PK == 0 {
			return true
		}
		return pk[i].PK < pk[j].PK
	})
	var fields []string
	for _, c := range pk {
		if c.PK > 0 {
			fields = append(fields, quoted(c.Name))
		}
	}
	if len(fields) == 0 {
		return "rowid"
	}
	return strings.Join(fields, ",")
}
func sqlCreate(t tableInfo) (string, error) {
	var parts []string
	var pk []column
	for _, c := range t.Columns {
		typ, err := columnType(c.Type)
		if err != nil {
			return "", err
		}
		s := quoted(c.Name) + " " + typ
		if c.NotNull || c.PK > 0 {
			s += " NOT NULL"
		}
		parts = append(parts, s)
		if c.PK > 0 {
			pk = append(pk, c)
		}
	}
	sort.Slice(pk, func(i, j int) bool { return pk[i].PK < pk[j].PK })
	if len(pk) > 0 {
		var names []string
		for _, c := range pk {
			names = append(names, quoted(c.Name))
		}
		parts = append(parts, "PRIMARY KEY ("+strings.Join(names, ",")+")")
	}
	parts = append(parts, `"_nl_import_ordinal" BIGINT NOT NULL UNIQUE`, `"_nl_import_digest" TEXT NOT NULL`)
	return "CREATE TABLE " + qualified(t.Name) + " (" + strings.Join(parts, ",") + ")", nil
}
func normalValue(v any, typ string) (any, error) {
	if v == nil {
		return nil, nil
	}
	sqlType, err := columnType(typ)
	if err != nil {
		return nil, err
	}
	switch sqlType {
	case "TEXT":
		switch x := v.(type) {
		case string:
			return x, nil
		case []byte:
			return string(x), nil
		}
	case "BYTEA":
		switch x := v.(type) {
		case []byte:
			return x, nil
		case string:
			return []byte(x), nil
		}
	case "BIGINT":
		if x, ok := v.(int64); ok {
			return x, nil
		}
	case "DOUBLE PRECISION":
		switch x := v.(type) {
		case float64:
			return x, nil
		case int64:
			return float64(x), nil
		}
	}
	return nil, fmt.Errorf("Неожиданный тип значения SQLite %T для столбца %s", v, typ)
}
func rowDigest(vals []any) (string, []byte, error) {
	b, err := json.Marshal(vals)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), h[:], nil
}
func addDigest(h hash.Hash, d []byte) { _, _ = h.Write(d) }

// verifyRestoredCore запускает существующую авторитетную проверку SQLite Core
// на одноразовой восстановленной копии: хеши манифестов, отозванные сеансы, билеты,
// опубликованные указатели, задания и инварианты мостов и расширений. Исходная копия
// остаётся доступной только для чтения на протяжении импорта в PostgreSQL.
func verifyRestoredCore(ctx context.Context, backup string) error {
	dir, err := os.MkdirTemp(filepath.Dir(backup), ".nl-pg-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "core.db")
	if _, err = sqlitedurable.RestoreBackup(ctx, backup, copyPath, false); err != nil {
		return err
	}
	repo, err := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: copyPath})
	if err != nil {
		return err
	}
	return repo.Close() // OpenExisting уже проверяет все инварианты Core
}

// Import создаёт новое неизменяемое полностью проверенное зеркало PostgreSQL за одну
// сериализуемую транзакцию. Существующие схемы не затрагиваются; любое расхождение
// отменяет операцию и откатывает все скопированные данные. Это ТОЛЬКО промежуточный перенос:
// действующий репозиторий PostgreSQL использует другую схему и пока не может переключиться.
func Import(ctx context.Context, backupPath, postgresDSN string) (Report, error) {
	report := Report{Format: importVersion, PostgreSQLSchema: Schema, ReadyForBackendCutover: false}
	if strings.TrimSpace(postgresDSN) == "" {
		return report, errors.New("Требуется: PostgreSQL DSN")
	}
	manifest, err := sqlitedurable.VerifyBackup(ctx, backupPath)
	if err != nil {
		return report, fmt.Errorf("Проверка резервной копии: %w", err)
	}
	if manifest.SchemaVersion != sqlitecore.SchemaVersion {
		return report, fmt.Errorf("Требуется схема SQLite %d, получено %d", sqlitecore.SchemaVersion, manifest.SchemaVersion)
	}
	// Проверить инварианты приложения на изолированной восстановленной копии.
	// Открыть резервную копию с проверкой контрольной суммы в режиме записи/WAL.
	if err = verifyRestoredCore(ctx, backupPath); err != nil {
		return report, fmt.Errorf("Проверка согласованности приложения SQLite: %w", err)
	}
	report.SnapshotSHA256 = manifest.SHA256
	report.SQLiteSchema = manifest.SchemaVersion
	abs, err := filepath.Abs(backupPath)
	if err != nil {
		return report, err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(abs + suffix); e == nil {
			return report, fmt.Errorf("Снимок содержит небезопасный сопутствующий файл %s", suffix)
		} else if !os.IsNotExist(e) {
			return report, e
		}
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() + "?mode=ro&_pragma=foreign_keys(1)&_pragma=trusted_schema(OFF)"
	src, err := sql.Open("sqlite", dsn)
	if err != nil {
		return report, err
	}
	defer src.Close()
	src.SetMaxOpenConns(1)
	src.SetMaxIdleConns(1)
	if err = src.PingContext(ctx); err != nil {
		return report, err
	}
	if err = src.QueryRowContext(ctx, "PRAGMA user_version").Scan(&report.SQLiteSchema); err != nil {
		return report, err
	}
	if report.SQLiteSchema != sqlitecore.SchemaVersion {
		return report, errors.New("Схема снимка изменилась после проверки")
	}
	// Удерживайте одну транзакцию чтения SQLite, исключая изменение между проверкой и использованием.
	if _, err = src.ExecContext(ctx, "BEGIN"); err != nil {
		return report, err
	}
	defer src.ExecContext(context.Background(), "ROLLBACK")
	tableDefs, err := tables(ctx, src)
	if err != nil {
		return report, err
	}
	if err = requireCoreTables(tableDefs); err != nil {
		return report, err
	}
	pg, err := pgx.Connect(ctx, postgresDSN)
	if err != nil {
		return report, fmt.Errorf("Ошибка подключения PostgreSQL (%T; учётные данные скрыты)", err)
	}
	defer pg.Close(context.Background())
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return report, err
	}
	defer tx.Rollback(context.Background())
	// Блокировка в области транзакции согласует одновременные миграции.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(32011, 326)`); err != nil {
		return report, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, Schema).Scan(&exists); err != nil {
		return report, err
	}
	if exists {
		return report, fmt.Errorf("Целевая схема %s уже существует (перезапись запрещена)", Schema)
	}
	if _, err = tx.Exec(ctx, "CREATE SCHEMA "+quoted(Schema)); err != nil {
		return report, err
	}
	for _, t := range tableDefs {
		stmt, e := sqlCreate(t)
		if e != nil {
			return report, e
		}
		if _, err = tx.Exec(ctx, stmt); err != nil {
			return report, fmt.Errorf("Создание: %s: %w", t.Name, err)
		}
	}
	for _, t := range tableDefs {
		result, e := copyAndVerify(ctx, src, tx, t)
		if e != nil {
			return report, fmt.Errorf("Копирование %s: %w", t.Name, e)
		}
		report.Tables = append(report.Tables, result)
		report.TotalRows += result.Rows
	}
	// Сохраняйте ограничения уникальности и ссылочной целостности в целевой базе,
	// а не только в манифесте. Данные загружаются до ограничений из-за циклов внешних ключей.
	if err = addUniqueIndexes(ctx, src, tx, tableDefs); err != nil {
		return report, err
	}
	if err = addForeignKeys(ctx, src, tx, tableDefs); err != nil {
		return report, err
	}
	for _, t := range tableDefs {
		if err = verifyPG(ctx, tx, t, report.Tables); err != nil {
			return report, err
		}
	}
	// Сохраните точный проверенный снимок SQLite вместе с реляционным зеркалом.
	// Обратный перенос сможет восстановить схему SQLite, индексы, триггеры, значения
	// и бинарное состояние без потерь при преобразовании типов SQL и DDL.
	if err = storeSnapshot(ctx, tx, backupPath, manifest); err != nil {
		return report, fmt.Errorf("Сохранение снимка SQLite: %w", err)
	}
	// Схема импорта намеренно защищена от append/UPDATE/DELETE. Рабочий
	// код должен начать обслуживать авторизацию из этого зеркала совместимости.
	_, err = tx.Exec(ctx, `CREATE FUNCTION `+quoted(Schema)+`.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Проверенный импорт Launcher неизменяем'; END $$`)
	if err != nil {
		return report, err
	}
	for _, t := range tableDefs {
		if err = protectTable(ctx, tx, t.Name); err != nil {
			return report, err
		}
	}
	if err = protectTable(ctx, tx, "migration_snapshot_chunks"); err != nil {
		return report, err
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return report, err
	}
	_, err = tx.Exec(ctx, `CREATE TABLE `+qualified("migration_receipt")+` (id TEXT PRIMARY KEY, report JSONB NOT NULL, backup_manifest JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	if err != nil {
		return report, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return report, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+qualified("migration_receipt")+`(id,report,backup_manifest) VALUES ($1,$2,$3)`, manifest.SHA256, string(reportJSON), string(manifestJSON))
	if err != nil {
		return report, err
	}
	if err = protectTable(ctx, tx, "migration_receipt"); err != nil {
		return report, err
	}
	// Перед фиксацией повторно проверьте байты копии и логические ограничения SQLite.
	again, e := sqlitedurable.VerifyBackup(ctx, backupPath)
	if e != nil {
		return report, e
	}
	if again.SHA256 != manifest.SHA256 {
		return report, errors.New("Исходный снимок изменился при импорте")
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("Перед повтором операции необходимо согласовать результат транзакции PostgreSQL: %w", err)
	}
	return report, nil
}

func copyAndVerify(ctx context.Context, db *sql.DB, tx pgx.Tx, t tableInfo) (TableResult, error) {
	out := TableResult{Name: t.Name}
	selectCols := make([]string, 0, len(t.Columns))
	copyCols := make([]string, 0, len(t.Columns)+2)
	for _, c := range t.Columns {
		selectCols = append(selectCols, quoted(c.Name))
		copyCols = append(copyCols, c.Name)
	}
	copyCols = append(copyCols, "_nl_import_ordinal", "_nl_import_digest")
	rows, err := db.QueryContext(ctx, "SELECT "+strings.Join(selectCols, ",")+" FROM "+quoted(t.Name)+" ORDER BY "+selectOrder(t))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	rolling := sha256.New()
	var buffer [][]any
	flush := func() error {
		if len(buffer) == 0 {
			return nil
		}
		n, e := tx.CopyFrom(ctx, pgx.Identifier{Schema, t.Name}, copyCols, pgx.CopyFromRows(buffer))
		if e != nil {
			return e
		}
		if n != int64(len(buffer)) {
			return errors.New("PostgreSQL COPY записал меньше строк, чем ожидалось")
		}
		buffer = nil
		return nil
	}
	for rows.Next() {
		raw := make([]any, len(t.Columns))
		ptr := make([]any, len(raw))
		for i := range raw {
			ptr[i] = &raw[i]
		}
		if err = rows.Scan(ptr...); err != nil {
			return out, err
		}
		normalized := make([]any, len(raw), len(raw)+2)
		for i, v := range raw {
			normalized[i], err = normalValue(v, t.Columns[i].Type)
			if err != nil {
				return out, fmt.Errorf("%s.%s: %w", t.Name, t.Columns[i].Name, err)
			}
		}
		digest, b, e := rowDigest(normalized)
		if e != nil {
			return out, e
		}
		addDigest(rolling, b)
		out.Rows++
		normalized = append(normalized, out.Rows, digest)
		buffer = append(buffer, normalized)
		if len(buffer) >= batchSize {
			if err = flush(); err != nil {
				return out, err
			}
		}
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = flush(); err != nil {
		return out, err
	}
	out.SHA256 = hex.EncodeToString(rolling.Sum(nil))
	return out, nil
}
func verifyPG(ctx context.Context, tx pgx.Tx, t tableInfo, results []TableResult) error {
	var expected TableResult
	for _, r := range results {
		if r.Name == t.Name {
			expected = r
			break
		}
	}
	var n int64
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+qualified(t.Name)).Scan(&n); err != nil {
		return err
	}
	if n != expected.Rows {
		return fmt.Errorf("В таблице %s не совпало число строк: SQLite %d, PostgreSQL %d", t.Name, expected.Rows, n)
	}
	fields := make([]string, 0, len(t.Columns)+2)
	for _, c := range t.Columns {
		fields = append(fields, quoted(c.Name))
	}
	fields = append(fields, "_nl_import_ordinal", "_nl_import_digest")
	rows, err := tx.Query(ctx, "SELECT "+strings.Join(fields, ",")+" FROM "+qualified(t.Name)+" ORDER BY _nl_import_ordinal")
	if err != nil {
		return err
	}
	h := sha256.New()
	var got int64
	for rows.Next() {
		values, e := rows.Values()
		if e != nil {
			err = e
			break
		}
		if len(values) != len(t.Columns)+2 {
			err = errors.New("Некорректная структура строки PostgreSQL")
			break
		}
		got++
		if ordinal, ok := values[len(t.Columns)].(int64); !ok || ordinal != got {
			err = fmt.Errorf("Нарушен порядок строк таблицы %s", t.Name)
			break
		}
		normalized := make([]any, len(t.Columns))
		for i, c := range t.Columns {
			normalized[i], e = normalValue(values[i], c.Type)
			if e != nil {
				break
			}
		}
		if e != nil {
			err = e
			break
		}
		digest, b, e := rowDigest(normalized)
		if e != nil {
			err = e
			break
		}
		stored, ok := values[len(values)-1].(string)
		if !ok || stored != digest {
			err = fmt.Errorf("В таблице %s содержимое PostgreSQL не совпадает в строке %d", t.Name, got)
			break
		}
		addDigest(h, b)
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	if got != n || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return fmt.Errorf("Ошибка криптографического согласования таблицы %s", t.Name)
	}
	return nil
}

func addUniqueIndexes(ctx context.Context, src *sql.DB, tx pgx.Tx, ts []tableInfo) error {
	for ti, t := range ts {
		rows, e := src.QueryContext(ctx, "PRAGMA index_list("+quoted(t.Name)+")")
		if e != nil {
			return e
		}
		type idx struct {
			name    string
			unique  int
			partial int
		}
		var indices []idx
		for rows.Next() {
			var seq int
			var item idx
			var origin string
			if e = rows.Scan(&seq, &item.name, &item.unique, &origin, &item.partial); e != nil {
				break
			}
			if item.unique == 1 && item.partial == 0 {
				indices = append(indices, item)
			}
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for ii, item := range indices {
			sub, e := src.QueryContext(ctx, "PRAGMA index_info("+quoted(item.name)+")")
			if e != nil {
				return e
			}
			var names []string
			for sub.Next() {
				var seq, cid int
				var n string
				if e = sub.Scan(&seq, &cid, &n); e != nil {
					break
				}
				if cid < 0 {
					e = fmt.Errorf("Уникальный индекс с выражением %s необходимо перенести вручную", item.name)
					break
				}
				names = append(names, quoted(n))
			}
			e = errors.Join(e, sub.Err(), sub.Close())
			if e != nil {
				return e
			}
			if len(names) == 0 {
				continue
			}
			indexName := fmt.Sprintf("nl_u_%d_%d", ti, ii)
			_, e = tx.Exec(ctx, "CREATE UNIQUE INDEX "+quoted(indexName)+" ON "+qualified(t.Name)+" ("+strings.Join(names, ",")+")")
			if e != nil {
				return fmt.Errorf("Уникальный индекс %s: %w", item.name, e)
			}
		}
	}
	return nil
}
func addForeignKeys(ctx context.Context, src *sql.DB, tx pgx.Tx, ts []tableInfo) error {
	for ti, t := range ts {
		rows, e := src.QueryContext(ctx, "PRAGMA foreign_key_list("+quoted(t.Name)+")")
		if e != nil {
			return e
		}
		type ref struct {
			id       int
			target   string
			from, to []string
		}
		var keys []ref
		for rows.Next() {
			var id, seq int
			var target, from, to, onUpdate, onDelete, match string
			if e = rows.Scan(&id, &seq, &target, &from, &to, &onUpdate, &onDelete, &match); e != nil {
				break
			}
			if len(keys) == 0 || keys[len(keys)-1].id != id {
				keys = append(keys, ref{id: id, target: target})
			}
			k := &keys[len(keys)-1]
			k.from = append(k.from, quoted(from))
			k.to = append(k.to, quoted(to))
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for _, k := range keys {
			name := fmt.Sprintf("nl_fk_%d_%d", ti, k.id)
			if len(k.to) == 0 || k.to[0] == `""` {
				return fmt.Errorf("Для неявного внешнего ключа SQLite в %s требуется явное сопоставление целевого первичного ключа", t.Name)
			}
			_, e = tx.Exec(ctx, "ALTER TABLE "+qualified(t.Name)+" ADD CONSTRAINT "+quoted(name)+" FOREIGN KEY ("+strings.Join(k.from, ",")+") REFERENCES "+qualified(k.target)+" ("+strings.Join(k.to, ",")+") DEFERRABLE INITIALLY DEFERRED")
			if e != nil {
				return fmt.Errorf("Внешний ключ %d таблицы %s: %w", k.id, t.Name, e)
			}
		}
	}
	return nil
}

// protectTable запрещает все изменяющие данные операции DML, включая TRUNCATE.
// В прежней реализации 0.32.11 триггер усечения ошибочно помещён
// в недостижимую ветвь ошибки; поэтому TRUNCATE мог обходить запрет.
func protectTable(ctx context.Context, tx pgx.Tx, table string) error {
	if _, err := tx.Exec(ctx, `CREATE TRIGGER nl_reject_mutation BEFORE INSERT OR UPDATE OR DELETE ON `+qualified(table)+` FOR EACH ROW EXECUTE FUNCTION `+quoted(Schema)+`.reject_mutation()`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `CREATE TRIGGER nl_reject_truncate BEFORE TRUNCATE ON `+qualified(table)+` FOR EACH STATEMENT EXECUTE FUNCTION `+quoted(Schema)+`.reject_mutation()`)
	return err
}

func storeSnapshot(ctx context.Context, tx pgx.Tx, path string, manifest sqlitedurable.BackupManifest) error {
	if _, err := tx.Exec(ctx, `CREATE TABLE `+qualified("migration_snapshot_chunks")+` (ordinal BIGINT PRIMARY KEY, sha256 TEXT NOT NULL, payload BYTEA NOT NULL)`); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	total := int64(0)
	digest := sha256.New()
	buffer := make([]byte, snapshotChunkSize)
	for seq := int64(0); ; seq++ {
		n, e := io.ReadFull(file, buffer)
		if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
			return e
		}
		if n == 0 {
			break
		}
		part := append([]byte(nil), buffer[:n]...)
		_, _ = digest.Write(part)
		sum := sha256.Sum256(part)
		if _, err := tx.Exec(ctx, `INSERT INTO `+qualified("migration_snapshot_chunks")+` (ordinal,sha256,payload) VALUES ($1,$2,$3)`, seq, hex.EncodeToString(sum[:]), part); err != nil {
			return err
		}
		total += int64(n)
		if e == io.EOF || e == io.ErrUnexpectedEOF {
			break
		}
	}
	if total != manifest.Bytes || hex.EncodeToString(digest.Sum(nil)) != manifest.SHA256 {
		return errors.New("Исходный снимок SQLite изменился при передаче")
	}
	return nil
}
