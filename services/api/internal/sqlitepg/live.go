package sqlitepg

// Живой импорт намеренно отделён от переноса неизменяемого промежуточного снимка.
// Он выполняется только в ПУСТОЙ базе SQLRepository с завершёнными миграциями.
// Непереносимое постоянное или защищённое состояние блокирует транзакцию: частичная
// миграция никогда не представляется как работоспособный проект.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"github.com/jackc/pgx/v5"
)

const liveImportVersion0473 = "sqlite-core-to-sqlrepository-0473-v1"

type LiveTable0473 struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Rows        int64  `json:"rows"`
}
type LiveReport0473 struct {
	Format                  string          `json:"format"`
	SourceSHA256            string          `json:"sourceSha256"`
	SQLiteSchema            int             `json:"sqliteSchema"`
	LiveTables              []LiveTable0473 `json:"liveTables"`
	Files                   int64           `json:"files"`
	LocalIdentities         int64           `json:"localIdentities"`
	StateVersion            string          `json:"stateVersion,omitempty"`
	ReauthenticatedSessions int64           `json:"reauthenticatedSessions"`
	FencedLeases            int64           `json:"fencedLeases"`
	Verified                bool            `json:"verified"`
	// Полное переключение дополнительно требует переноса данных сервисов и хранилища (0.47.4–0.47.5).
	ReadyForBackendCutover bool `json:"readyForBackendCutover"`
}

type liveRule0473 struct {
	source, target string
	columns        []string
	convert        func(map[string]any) (map[string]any, error)
}

func instant0473(v any, optional bool) (any, error) {
	n, ok := v.(int64)
	if !ok {
		return nil, fmt.Errorf("Для временной метки SQLite требуется целое число, получено %T", v)
	}
	if n == 0 && optional {
		return nil, nil
	}
	if n < 0 {
		return nil, fmt.Errorf("Отрицательная временная метка %d", n)
	}
	return time.Unix(0, n).UTC(), nil
}
func bool0473(v any) (any, error) {
	n, ok := v.(int64)
	if !ok || (n != 0 && n != 1) {
		return nil, fmt.Errorf("Некорректное логическое значение SQLite: %v", v)
	}
	return n == 1, nil
}
func json0473(v any) (any, error) {
	s, ok := v.(string)
	if !ok || !json.Valid([]byte(s)) {
		return nil, errors.New("Некорректный JSON в промежуточной записи")
	}
	return s, nil
}
func t0473(fields ...string) []string { return fields }
func copyFields0473(src map[string]any, names ...string) (map[string]any, error) {
	out := make(map[string]any, len(names))
	for _, name := range names {
		v, ok := src[name]
		if !ok {
			return nil, fmt.Errorf("Отсутствует исходный столбец %q", name)
		}
		out[name] = v
	}
	return out, nil
}
func translate0473(src map[string]any, names []string, times []string, optional []string, booleans []string, jsonFields []string) (map[string]any, error) {
	dst, err := copyFields0473(src, names...)
	if err != nil {
		return nil, err
	}
	for _, name := range times {
		dst[name], err = instant0473(dst[name], false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for _, name := range optional {
		dst[name], err = instant0473(dst[name], true)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for _, name := range booleans {
		dst[name], err = bool0473(dst[name])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for _, name := range jsonFields {
		dst[name], err = json0473(dst[name])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return dst, nil
}
func generic0473(src, target string, fields, times, optional, booleans, js []string) liveRule0473 {
	return liveRule0473{src, target, fields, func(row map[string]any) (map[string]any, error) {
		return translate0473(row, fields, times, optional, booleans, js)
	}}
}
func rules0473() []liveRule0473 {
	return []liveRule0473{
		generic0473("projects", "projects", t0473("id", "name", "description", "homepage", "repository", "default_channel", "created_at", "updated_at"), t0473("created_at", "updated_at"), nil, nil, nil),
		generic0473("profiles", "profiles", t0473("project_id", "id", "name", "description", "loader", "preset", "is_default", "minecraft_version", "loader_version", "java_major", "revision", "digest", "created_at", "updated_at"), t0473("created_at", "updated_at"), nil, t0473("is_default"), nil),
		generic0473("profile_revisions", "profile_revisions_0221", t0473("project_id", "profile_id", "revision", "schema_version", "digest", "spec", "created_at"), t0473("created_at"), nil, nil, t0473("spec")),
		generic0473("channels", "release_channels", t0473("project_id", "id", "name", "description", "protected"), nil, nil, t0473("protected"), nil),
		generic0473("roles", "roles", t0473("id", "name", "description", "permissions"), nil, nil, nil, t0473("permissions")),
		generic0473("users", "users", t0473("id", "email", "display_name", "role_id", "status", "password_hash", "password_updated_at", "last_login_at", "disabled_at", "created_at", "updated_at"), t0473("created_at", "updated_at"), t0473("password_updated_at", "last_login_at", "disabled_at"), nil, nil),
		generic0473("project_user_roles", "project_user_roles", t0473("user_id", "project_id", "role_id"), nil, nil, nil, nil),
		generic0473("audit_events", "audit_events", t0473("id", "actor", "action", "target", "ip", "user_agent", "created_at", "correlation_id", "reason_code", "job_id"), t0473("created_at"), nil, nil, nil),
		generic0473("releases", "release_versions", t0473("id", "project_id", "profile_id", "channel", "version", "status", "manifest", "published_at"), nil, t0473("published_at"), nil, t0473("manifest")),
		generic0473("channel_heads", "channel_heads", t0473("project_id", "profile_id", "channel", "revision", "release_id", "version", "manifest_digest", "updated_at"), t0473("updated_at"), nil, nil, nil),
	}
}
func rowColumns0473(ctx context.Context, tx pgx.Tx, table string) ([]column, error) {
	rows, err := tx.Query(ctx, `SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 ORDER BY ordinal_position`, Schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []column
	for rows.Next() {
		var c column
		var typ string
		if err = rows.Scan(&c.Name, &typ); err != nil {
			return nil, err
		}
		if strings.HasPrefix(c.Name, "_nl_import_") {
			continue
		}
		switch typ {
		case "text":
			c.Type = "TEXT"
		case "bigint":
			c.Type = "INTEGER"
		case "bytea":
			c.Type = "BLOB"
		case "double precision":
			c.Type = "REAL"
		default:
			return nil, fmt.Errorf("Некорректный тип промежуточного столбца %s.%s: %s", table, c.Name, typ)
		}
		out = append(out, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Пустая промежуточная таблица %s", table)
	}
	return out, nil
}
func validateCatalog0473(ctx context.Context, tx pgx.Tx) error {
	migrations, err := dbmigrate.Catalog()
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT version,checksum FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("Сначала необходимо применить миграции PostgreSQL: %w", err)
	}
	applied := map[string]string{}
	for rows.Next() {
		var v, c string
		if err = rows.Scan(&v, &c); err != nil {
			break
		}
		applied[v] = c
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	if len(applied) != len(migrations) {
		return fmt.Errorf("Миграции SQLRepository неполны или неизвестны: получено %d, ожидалось %d", len(applied), len(migrations))
	}
	for _, m := range migrations {
		if applied[m.Version] != m.Checksum {
			return fmt.Errorf("Миграция SQLRepository %s не применена или изменена", m.Version)
		}
	}
	return nil
}
func emptyLive0473(ctx context.Context, tx pgx.Tx) error {
	// Новая схема SQLRepository предварительно создаёт роли; иные данные недопустимы.
	seeded := map[string]string{
		"launcher_installation_state":  `singleton=true AND bootstrap_token_hash='' AND bootstrap_token_used_at IS NULL AND installation_completed=false AND completed_at IS NULL`,
		"extension_ga_contract":        `singleton=true AND package_format_version='1.0' AND manifest_schema_version='2.0' AND host_protocol_version='1.0' AND extension_api_version='1.0' AND legacy_api_aliases='["3.7"]'::jsonb`,
		"extension_trust_policy":       `singleton=true AND mode='strict' AND allowed_publishers='[]'::jsonb`,
		"operational_config_current":   `id=1 AND revision=1 AND settings='{"auditDefaultPageSize":25,"auditMaxPageSize":100,"auditLookbackDays":30,"auditExposeClientDetails":false,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}'::jsonb`,
		"operational_config_revisions": `revision=1 AND actor='system' AND reason='initial defaults' AND restored_from IS NULL AND settings='{"auditDefaultPageSize":25,"auditMaxPageSize":100,"auditLookbackDays":30,"auditExposeClientDetails":false,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}'::jsonb`,
	}
	rows, err := tx.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename NOT IN ('schema_migrations','roles') ORDER BY tablename`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			break
		}
		tables = append(tables, name)
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	for _, name := range tables {
		safe, err := identifier(name)
		if err != nil {
			return err
		}
		var count int64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM `+safe).Scan(&count); err != nil {
			return err
		}
		if expected, ok := seeded[name]; ok {
			if count != 1 {
				return fmt.Errorf("Начальные данные SQLRepository %s содержат %d записей вместо одной", name, count)
			}
			var valid int64
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM `+safe+` WHERE `+expected).Scan(&valid); err != nil {
				return err
			}
			if valid != 1 {
				return fmt.Errorf("Начальные данные SQLRepository %s изменены", name)
			}
		} else if count != 0 {
			return fmt.Errorf("Целевая таблица SQLRepository %s не пуста (%d записей)", name, count)
		}
	}
	return nil
}
func tableReport0473(report Report, name string) (TableResult, bool) {
	for _, t := range report.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return TableResult{}, false
}
func sourceRows0473(ctx context.Context, tx pgx.Tx, name string, expected TableResult, callback func(map[string]any) error) error {
	cs, err := rowColumns0473(ctx, tx, name)
	if err != nil {
		return err
	}
	cols := make([]string, 0, len(cs)+2)
	for _, c := range cs {
		cols = append(cols, quoted(c.Name))
	}
	cols = append(cols, `"_nl_import_ordinal"`, `"_nl_import_digest"`)
	// pgx.Conn не может выполнять INSERT при открытом потоке результатов предыдущего запроса.
	// Читайте ограниченные порции, закрывайте набор результатов и только затем записывайте порцию.
	query := `SELECT ` + strings.Join(cols, ",") + ` FROM ` + qualified(name) + ` WHERE "_nl_import_ordinal" > $1 ORDER BY "_nl_import_ordinal" LIMIT $2`
	h := sha256.New()
	var count int64
	for {
		rows, e := tx.Query(ctx, query, count, batchSize)
		if e != nil {
			return e
		}
		batch := make([]map[string]any, 0, batchSize)
		for rows.Next() {
			vals, er := rows.Values()
			if er != nil {
				e = er
				break
			}
			if len(vals) != len(cs)+2 {
				e = fmt.Errorf("Некорректная структура промежуточной записи в %s", name)
				break
			}
			count++
			if seq, ok := vals[len(cs)].(int64); !ok || seq != count {
				e = fmt.Errorf("Несовпадение порядка подготовленных строк в %s", name)
				break
			}
			out := make(map[string]any, len(cs))
			normalized := make([]any, len(cs))
			for i, c := range cs {
				normalized[i], er = normalValue(vals[i], c.Type)
				if er != nil {
					break
				}
				out[c.Name] = normalized[i]
			}
			if er != nil {
				e = er
				break
			}
			digest, hashBytes, er := rowDigest(normalized)
			if er != nil {
				e = er
				break
			}
			if stored, ok := vals[len(cs)+1].(string); !ok || stored != digest {
				e = fmt.Errorf("Контрольная сумма подготовленной строки %s не совпадает на позиции %d", name, count)
				break
			}
			addDigest(h, hashBytes)
			batch = append(batch, out)
		}
		e = errors.Join(e, rows.Err())
		rows.Close()
		if e != nil {
			return e
		}
		if callback != nil {
			for _, row := range batch {
				if e = callback(row); e != nil {
					return e
				}
			}
		}
		if len(batch) < batchSize {
			break
		}
	}
	if count != expected.Rows || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return fmt.Errorf("Количество записей или SHA-256 промежуточной таблицы %s не совпадает", name)
	}
	return nil
}
func insert0473(ctx context.Context, tx pgx.Tx, table string, data map[string]any, fields []string) error {
	dest, err := identifier(table)
	if err != nil {
		return err
	}
	columns := make([]string, 0, len(fields))
	params := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields))
	for i, name := range fields {
		q, er := identifier(name)
		if er != nil {
			return er
		}
		v, ok := data[name]
		if !ok {
			return fmt.Errorf("Отсутствует сопоставленное поле %s.%s", table, name)
		}
		columns = append(columns, q)
		param := fmt.Sprintf("$%d", i+1)
		if (table == "users" && name == "project_roles") || (table == "profile_revisions_0221" && name == "spec") || (table == "release_versions" && name == "manifest") {
			param += "::text::jsonb"
		}
		params = append(params, param)
		args = append(args, v)
	}
	_, err = tx.Exec(ctx, `INSERT INTO `+dest+`(`+strings.Join(columns, ",")+`) VALUES(`+strings.Join(params, ",")+`)`, args...)
	return err
}
func installLocalIdentity0473(ctx context.Context, tx pgx.Tx, u map[string]any) error {
	id, ok := u["id"].(string)
	if !ok || id == "" {
		return errors.New("Отсутствует идентификатор пользователя")
	}
	email, ok := u["email"].(string)
	if !ok || email == "" {
		return errors.New("Отсутствует электронная почта пользователя")
	}
	display, ok := u["display_name"].(string)
	if !ok {
		return errors.New("Отсутствует отображаемое имя пользователя")
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth_identities(id,user_id,provider,issuer,subject,email,username,display_name,claims,created_at,updated_at)
        VALUES($1,$2,'local','launcher',$2,$3,$3,$4,'{}'::jsonb,$5,$6)`, "identity-local-"+id, id, email, display, u["created_at"], u["updated_at"])
	return err
}

func installRoles0473(ctx context.Context, tx pgx.Tx, expected TableResult) error {
	// Предварительно созданные роли PostgreSQL заменяются точно ролями источника.
	// Изменить идентификаторы ролей, используемых существующими пользователями, нельзя:
	// emptyLive0473 уже исключил наличие прежних учётных записей.
	if _, err := tx.Exec(ctx, `DELETE FROM roles`); err != nil {
		return err
	}
	return sourceRows0473(ctx, tx, "roles", expected, func(src map[string]any) error {
		fields := t0473("id", "name", "description", "permissions")
		data, err := translate0473(src, fields, nil, nil, nil, t0473("permissions"))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO roles(id,name,description,permissions) VALUES ($1,$2,$3,$4::text::jsonb)`, data["id"], data["name"], data["description"], data["permissions"])
		return err
	})
}
func checkManifest0473(src map[string]any) error {
	s, ok := src["manifest"].(string)
	if !ok {
		return errors.New("Отсутствует JSON подписанного выпуска")
	}
	var m model.Manifest
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return err
	}
	if err := model.ValidateManifestSchema(m); err != nil {
		return err
	}
	for field, val := range map[string]string{"project_id": m.ProjectID, "profile_id": m.ProfileID, "channel": m.Channel, "version": m.Version} {
		if src[field] != val {
			return fmt.Errorf("Несоответствие: манифест %s", field)
		}
	}
	if src["status"] == "published" && m.Signature == nil {
		return errors.New("У опубликованного релиза отсутствует подпись")
	}
	return nil
}
func verifyLive0473(ctx context.Context, tx pgx.Tx, table string, expected int64) error {
	q, err := identifier(table)
	if err != nil {
		return err
	}
	var count int64
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM "+q).Scan(&count); err != nil {
		return err
	}
	if count != expected {
		return fmt.Errorf("Число строк в работающей таблице %s не совпадает: %d != %d", table, count, expected)
	}
	return nil
}
func fileRows0473(ctx context.Context, tx pgx.Tx) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT id,project_id,manifest::text FROM release_versions`)
	if err != nil {
		return 0, err
	}
	type release struct{ id, project, raw string }
	var releases []release
	for rows.Next() {
		var r release
		if err = rows.Scan(&r.id, &r.project, &r.raw); err != nil {
			break
		}
		releases = append(releases, r)
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return 0, err
	}
	var count int64
	for _, r := range releases {
		var m model.Manifest
		if err = json.Unmarshal([]byte(r.raw), &m); err != nil {
			return 0, err
		}
		if err = model.ValidateManifestSchema(m); err != nil {
			return 0, err
		}
		for _, f := range m.Files {
			h := sha256.Sum256([]byte(r.id + "\x00" + f.Path))
			id := "migrated-" + hex.EncodeToString(h[:])
			targetOS, er := json.Marshal(f.TargetOS)
			if er != nil {
				return 0, er
			}
			mirrorList := f.Mirrors
			if mirrorList == nil {
				mirrorList = []string{}
			}
			mirrors, er := json.Marshal(mirrorList)
			if er != nil {
				return 0, er
			}
			_, er = tx.Exec(ctx, `INSERT INTO files(id,project_id,version_id,path,size,sha256,url,required,executable,target_os,ownership,mirrors) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb,$11,$12::text::jsonb)`, id, r.project, r.id, f.Path, f.Size, f.SHA256, f.URL, f.Required, f.Executable, string(targetOS), f.Ownership, string(mirrors))
			if er != nil {
				return 0, fmt.Errorf("Релиз %s, файл %s: %w", r.id, f.Path, er)
			}
			count++
		}
	}
	return count, nil
}
func verifyFK0473(ctx context.Context, tx pgx.Tx) error {
	var missing int64
	checks := []string{
		`SELECT count(*) FROM profiles p LEFT JOIN projects q ON q.id=p.project_id WHERE q.id IS NULL`,
		`SELECT count(*) FROM release_versions r LEFT JOIN profiles p ON p.project_id=r.project_id AND p.id=r.profile_id WHERE p.id IS NULL`,
		`SELECT count(*) FROM release_versions r LEFT JOIN release_channels c ON c.project_id=r.project_id AND c.id=r.channel WHERE c.id IS NULL`,
		`SELECT count(*) FROM channel_heads h LEFT JOIN release_versions r ON r.id=h.release_id AND r.project_id=h.project_id AND r.profile_id=h.profile_id AND r.channel=h.channel AND r.status='published' WHERE r.id IS NULL`,
		`SELECT count(*) FROM project_user_roles ur LEFT JOIN users u ON u.id=ur.user_id LEFT JOIN projects p ON p.id=ur.project_id LEFT JOIN roles r ON r.id=ur.role_id WHERE u.id IS NULL OR p.id IS NULL OR r.id IS NULL`,
	}
	for _, q := range checks {
		if err := tx.QueryRow(ctx, q).Scan(&missing); err != nil {
			return err
		}
		if missing != 0 {
			return fmt.Errorf("Ошибка проверки связей SQLRepository: %s (%d)", q, missing)
		}
	}
	return nil
}

// PopulateLive0473 преобразует неизменяемый проверенный импорт SQLite во
// фактические таблицы SQLRepository. Требуются все миграции схемы PostgreSQL,
// пустая целевая база и ПОЛНОЕ отсутствие непереносимого состояния. Операция
// вместе с квитанцией и проверками внешних ключей атомарна; частично заполненных таблиц нет.
func PopulateLive0473(ctx context.Context, postgresDSN string) (LiveReport0473, error) {
	return PopulateLiveWithMFA0474(ctx, postgresDSN, MFASecrets0474{})
}

// PopulateLiveWithMFA0474 сохраняет включённую MFA путём криптографической перепаковки
// каждого секрета AES-GCM. Импорт атомарен; отсутствие ключа вызывает полный откат.
func PopulateLiveWithMFA0474(ctx context.Context, postgresDSN string, keys MFASecrets0474) (LiveReport0473, error) {
	report := LiveReport0473{Format: liveImportVersion0473}
	if strings.TrimSpace(postgresDSN) == "" {
		return report, errors.New("Необходимо указать DSN PostgreSQL")
	}
	pg, err := pgx.Connect(ctx, postgresDSN)
	if err != nil {
		return report, fmt.Errorf("Подключение PostgreSQL (%T; учётные данные скрыты)", err)
	}
	defer pg.Close(context.Background())
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return report, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(32011, 326)`); err != nil {
		return report, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(718033100100)`); err != nil {
		return report, err
	}
	// Убедитесь, что схемы и таблицы ищутся в одной ожидаемой схеме приложения.
	var current string
	if err = tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&current); err != nil {
		return report, err
	}
	if current != "public" {
		return report, fmt.Errorf("SQLRepository должен использовать схему public, получено %s", current)
	}
	if err = validateCatalog0473(ctx, tx); err != nil {
		return report, err
	}
	if err = emptyLive0473(ctx, tx); err != nil {
		return report, err
	}
	var raw string
	if err = tx.QueryRow(ctx, `SELECT report::text FROM `+qualified("migration_receipt")+` LIMIT 1`).Scan(&raw); err != nil {
		return report, fmt.Errorf("Не найдена проверенная квитанция промежуточного переноса: %w", err)
	}
	var original Report
	if err = json.Unmarshal([]byte(raw), &original); err != nil {
		return report, err
	}
	if original.Format != importVersion || original.SQLiteSchema != sqlitecore.SchemaVersion || len(original.SnapshotSHA256) != 64 || original.PostgreSQLSchema != Schema {
		return report, errors.New("Некорректная квитанция или схема промежуточного переноса")
	}
	report.SourceSHA256 = original.SnapshotSHA256
	report.SQLiteSchema = original.SQLiteSchema
	rules := rules0473()
	allow := make(map[string]bool, len(rules))
	for _, rule := range rules {
		allow[rule.source] = true
	}
	for _, rule := range stateRules0474() {
		allow[rule.source] = true
	}
	// При неожиданных или дублированных объявлениях таблиц и данных завершайте операцию отказом.
	// Это касается и удалённых или изменённых записей таблиц, не выбранных для импорта.
	seen := map[string]bool{}
	for _, table := range original.Tables {
		if seen[table.Name] || table.Rows < 0 || len(table.SHA256) != 64 {
			return report, fmt.Errorf("Некорректная или повторяющаяся квитанция подготовленной таблицы %q", table.Name)
		}
		seen[table.Name] = true
		if !allow[table.Name] {
			if _, e := identifier(table.Name); e != nil {
				return report, e
			}
			var n int64
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM `+qualified(table.Name)).Scan(&n); e != nil {
				return report, e
			}
			if n != table.Rows {
				return report, fmt.Errorf("Не совпадает количество записей промежуточной таблицы %s", table.Name)
			}
			if n > 0 {
				return report, fmt.Errorf("Нельзя импортировать в рабочую систему %d записей из неподдерживаемой таблицы SQLite %s", n, table.Name)
			}
		}
	}
	rows, e := tx.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema=$1 AND table_type='BASE TABLE' AND table_name NOT IN ('migration_snapshot_chunks','migration_receipt')`, Schema)
	if e != nil {
		return report, e
	}
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			break
		}
		if !seen[name] {
			e = fmt.Errorf("Незарегистрированная таблица подготовки %s", name)
			break
		}
	}
	e = errors.Join(e, rows.Err())
	rows.Close()
	if e != nil {
		return report, e
	}
	for _, rule := range rules {
		if _, found := tableReport0473(original, rule.source); !found {
			return report, fmt.Errorf("Отсутствует обязательная промежуточная таблица %s", rule.source)
		}
	}
	if err = prepareState0474(ctx, tx); err != nil {
		return report, err
	}
	for _, rule := range rules {
		expected, _ := tableReport0473(original, rule.source)
		if rule.source == "roles" {
			err = installRoles0473(ctx, tx, expected)
		} else {
			err = sourceRows0473(ctx, tx, rule.source, expected, func(row map[string]any) error {
				if rule.source == "releases" {
					if e := checkManifest0473(row); e != nil {
						return e
					}
				}
				dst, e := rule.convert(row)
				if e != nil {
					return e
				}
				// SQLRepository считывает published_at в time.Time, а не sql.NullTime.
				// Сохранить нулевое/неопубликованное состояние Core в читаемом виде.
				if rule.source == "releases" && dst["published_at"] == nil {
					dst["published_at"] = time.Time{}
				}
				if rule.source == "users" {
					if epoch, ok := row["auth_epoch"].(int64); !ok || epoch < 1 {
						return fmt.Errorf("Некорректное значение: пользователь auth_epoch %v", row["auth_epoch"])
					}
					dst["core_auth_epoch_0474"] = row["auth_epoch"]
					dst["project_roles"] = "{}"
				}
				e = insert0473(ctx, tx, rule.target, dst, append(append([]string(nil), rule.columns...), func() []string {
					// SQLRepository считывает published_at в time.Time, а не sql.NullTime.
					// Сохранить нулевое/неопубликованное состояние Core в читаемом виде.
					if rule.source == "releases" && dst["published_at"] == nil {
						dst["published_at"] = time.Time{}
					}
					if rule.source == "users" {
						return []string{"project_roles", "core_auth_epoch_0474"}
					}
					return nil
				}()...))
				if e != nil {
					return e
				}
				if rule.source == "users" {
					return installLocalIdentity0473(ctx, tx, dst)
				}
				return nil
			})
		}
		if err != nil {
			return report, fmt.Errorf("Импорт в работающую систему %s -> %s: %w", rule.source, rule.target, err)
		}
		if err = verifyLive0473(ctx, tx, rule.target, expected.Rows); err != nil {
			return report, err
		}
		report.LiveTables = append(report.LiveTables, LiveTable0473{Source: rule.source, Destination: rule.target, Rows: expected.Rows})
		if rule.source == "users" {
			report.LocalIdentities = expected.Rows
			if err = verifyLive0473(ctx, tx, "auth_identities", expected.Rows); err != nil {
				return report, err
			}
		}
	}
	if err = moveState0474(ctx, tx, original, &report, keys); err != nil {
		return report, err
	}
	report.StateVersion = stateVersion0474
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM auth_sessions WHERE core_original_status_0474='active' AND status='revoked'`).Scan(&report.ReauthenticatedSessions); err != nil {
		return report, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM durable_scope_leases`).Scan(&report.FencedLeases); err != nil {
		return report, err
	}
	if report.Files, err = fileRows0473(ctx, tx); err != nil {
		return report, fmt.Errorf("Импорт файла манифеста: %w", err)
	}
	if err = verifyLive0473(ctx, tx, "files", report.Files); err != nil {
		return report, err
	}
	if _, err = tx.Exec(ctx, `UPDATE users u SET project_roles=COALESCE((SELECT jsonb_object_agg(ur.project_id,ur.role_id) FROM project_user_roles ur WHERE ur.user_id=u.id),'{}'::jsonb)`); err != nil {
		return report, err
	}
	// Импорт настоящего владельца и проекта не должен заново активировать создание первого администратора.
	if _, err = tx.Exec(ctx, `UPDATE launcher_installation_state SET installation_completed=true,completed_at=now(),updated_at=now() WHERE singleton=true AND EXISTS(SELECT 1 FROM users) AND EXISTS(SELECT 1 FROM projects)`); err != nil {
		return report, err
	}
	if err = verifyFK0473(ctx, tx); err != nil {
		return report, err
	}
	// Сохраните квитанцию в той же живой транзакции. Старые миграции SQL не меняйте.
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS sqlite_live_receipts_0473(source_sha256 TEXT PRIMARY KEY,report JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return report, err
	}
	report.Verified = true
	data, err := json.Marshal(report)
	if err != nil {
		return report, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sqlite_live_receipts_0473(source_sha256,report) VALUES($1,$2::text::jsonb)`, report.SourceSHA256, string(data)); err != nil {
		return report, err
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("Результат применения переноса должен быть согласован: %w", err)
	}
	return report, nil
}

// Защита на этапе компиляции от изменения потоковой проверки SHA-256.
