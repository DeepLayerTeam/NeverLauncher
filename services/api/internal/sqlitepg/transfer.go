// Package sqlitepg transfers an immutable, verified SQLite 326 snapshot into a
// PostgreSQL quarantine schema. It never changes the live PostgreSQL tables or
// enables an unsafe backend cutover. It preserves every source table/row/column,
// including audit, revoked tokens, join tickets, UUIDs, binary blobs and leases.
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
		return "", fmt.Errorf("unsafe SQL identifier %q", name)
	}
	// No SQL interpolation is used for VALUES. Identifiers are always quoted.
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
		return "", fmt.Errorf("unsupported SQLite column affinity %q", typ)
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
			return nil, fmt.Errorf("%s: generated/hidden SQLite column is unsupported", table)
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
		return nil, fmt.Errorf("%s: table has no columns", table)
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
			return fmt.Errorf("SQLite schema 326 is missing mandatory durable table %q", name)
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
	return nil, fmt.Errorf("unexpected SQLite value type %T for column %s", v, typ)
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

// verifyRestoredCore runs the existing authoritative SQLite Core Check on a
// disposable restore, covering manifest hashes, revoked sessions, tickets,
// published heads, jobs and bridge/extension invariants. The source backup is
// opened read-only throughout the actual PostgreSQL import.
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
	return repo.Close() // OpenExisting already runs every Core invariant check
}

// Import creates a new, immutable, fully verified PostgreSQL mirror in one
// serializable transaction. Existing PG schemas are untouched; any mismatch
// aborts and rolls back all copied data. This is a staging transfer ONLY:
// PostgreSQL's live repository uses a different schema and cannot yet cut over.
func Import(ctx context.Context, backupPath, postgresDSN string) (Report, error) {
	report := Report{Format: importVersion, PostgreSQLSchema: Schema, ReadyForBackendCutover: false}
	if strings.TrimSpace(postgresDSN) == "" {
		return report, errors.New("PostgreSQL DSN is required")
	}
	manifest, err := sqlitedurable.VerifyBackup(ctx, backupPath)
	if err != nil {
		return report, fmt.Errorf("backup verification: %w", err)
	}
	if manifest.SchemaVersion != sqlitecore.SchemaVersion {
		return report, fmt.Errorf("required SQLite schema %d, got %d", sqlitecore.SchemaVersion, manifest.SchemaVersion)
	}
	// Verify application-level invariants against an isolated restored copy.
	// Never open the checksum-protected backup in writable/WAL mode.
	if err = verifyRestoredCore(ctx, backupPath); err != nil {
		return report, fmt.Errorf("SQLite application consistency: %w", err)
	}
	report.SnapshotSHA256 = manifest.SHA256
	report.SQLiteSchema = manifest.SchemaVersion
	abs, err := filepath.Abs(backupPath)
	if err != nil {
		return report, err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(abs + suffix); e == nil {
			return report, fmt.Errorf("snapshot has unsafe %s sidecar", suffix)
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
		return report, errors.New("snapshot schema changed after verification")
	}
	// Hold a single SQLite read transaction to prevent time-of-check/time-of-use changes.
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
		return report, fmt.Errorf("PostgreSQL connection failed (%T; credentials redacted)", err)
	}
	defer pg.Close(context.Background())
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return report, err
	}
	defer tx.Rollback(context.Background())
	// Acquiring a transaction-scoped lock coordinates simultaneous migrations.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(32011, 326)`); err != nil {
		return report, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, Schema).Scan(&exists); err != nil {
		return report, err
	}
	if exists {
		return report, fmt.Errorf("target schema %s already exists (refusing overwrite)", Schema)
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
			return report, fmt.Errorf("create %s: %w", t.Name, err)
		}
	}
	for _, t := range tableDefs {
		result, e := copyAndVerify(ctx, src, tx, t)
		if e != nil {
			return report, fmt.Errorf("copy %s: %w", t.Name, e)
		}
		report.Tables = append(report.Tables, result)
		report.TotalRows += result.Rows
	}
	// Keep relational uniqueness and references in the target, not just in
	// a manifest. Data are imported before constraints to handle FK cycles.
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
	// Save the exact verified SQLite snapshot alongside the relational mirror.
	// A reverse transfer can reproduce SQLite schema, indexes, triggers, values,
	// and binary state without lossy SQL type/DDL translations.
	if err = storeSnapshot(ctx, tx, backupPath, manifest); err != nil {
		return report, fmt.Errorf("store SQLite snapshot: %w", err)
	}
	// The import schema is deliberately append/UPDATE/DELETE protected. Live
	// code must never start serving auth from this compatibility mirror.
	_, err = tx.Exec(ctx, `CREATE FUNCTION `+quoted(Schema)+`.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Launcher verified import is immutable'; END $$`)
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
	// Recheck backup bytes and SQLite logical constraints before commit.
	again, e := sqlitedurable.VerifyBackup(ctx, backupPath)
	if e != nil {
		return report, e
	}
	if again.SHA256 != manifest.SHA256 {
		return report, errors.New("source snapshot changed during import")
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("PostgreSQL commit outcome must be reconciled before retry: %w", err)
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
			return errors.New("PostgreSQL COPY wrote fewer rows")
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
		return fmt.Errorf("%s row count mismatch SQLite %d PG %d", t.Name, expected.Rows, n)
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
			err = errors.New("invalid PG row shape")
			break
		}
		got++
		if ordinal, ok := values[len(t.Columns)].(int64); !ok || ordinal != got {
			err = fmt.Errorf("%s row order mismatch", t.Name)
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
			err = fmt.Errorf("%s PG payload mismatch on row %d", t.Name, got)
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
		return fmt.Errorf("%s cryptographic reconciliation failed", t.Name)
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
					e = fmt.Errorf("expression-based unique index %s requires manual translation", item.name)
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
				return fmt.Errorf("unique index %s: %w", item.name, e)
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
				return fmt.Errorf("implicit SQLite FK on %s needs explicit target PK mapping", t.Name)
			}
			_, e = tx.Exec(ctx, "ALTER TABLE "+qualified(t.Name)+" ADD CONSTRAINT "+quoted(name)+" FOREIGN KEY ("+strings.Join(k.from, ",")+") REFERENCES "+qualified(k.target)+" ("+strings.Join(k.to, ",")+") DEFERRABLE INITIALLY DEFERRED")
			if e != nil {
				return fmt.Errorf("%s FK %d: %w", t.Name, k.id, e)
			}
		}
	}
	return nil
}

// protectTable rejects every data-changing DML operation, including TRUNCATE.
// The earlier 0.32.11 implementation mistakenly placed the truncate trigger
// inside an unreachable error branch; that made TRUNCATE a possible bypass.
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
		return errors.New("source SQLite snapshot changed while transferring")
	}
	return nil
}
