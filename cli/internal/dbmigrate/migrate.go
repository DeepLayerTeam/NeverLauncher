package dbmigrate

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

//go:embed sql/*.sql
var migrationFS embed.FS

type Migration struct{ Version, Checksum, SQL string }

func List() ([]Migration, error) {
	entries, err := migrationFS.ReadDir("sql")
	if err != nil {
		return nil, err
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrationFS.ReadFile("sql/" + e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, Migration{Version: strings.TrimSuffix(e.Name(), ".sql"), Checksum: hex.EncodeToString(sum[:]), SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func sqlLiteral(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

func expectedValuesSQL(ms []Migration) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, "("+sqlLiteral(m.Version)+","+sqlLiteral(m.Checksum)+")")
	}
	return strings.Join(parts, ",")
}

func knownVersionsSQL(ms []Migration) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, sqlLiteral(m.Version))
	}
	return strings.Join(parts, ",")
}

func BuildApplyScript() (string, error) {
	ms, err := List()
	if err != nil {
		return "", err
	}
	if len(ms) == 0 {
		return "", fmt.Errorf("migration catalog is empty")
	}
	var b strings.Builder
	b.WriteString("\\set ON_ERROR_STOP on\nSELECT pg_advisory_lock(718033100100);\n")
	b.WriteString(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', applied_at TIMESTAMPTZ NOT NULL DEFAULT now());` + "\n")
	b.WriteString(`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS version TEXT; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT ''; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ NOT NULL DEFAULT now();` + "\n")
	b.WriteString(`DO $$ BEGIN IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migrations' AND column_name='id') THEN EXECUTE 'UPDATE schema_migrations SET version=id WHERE version IS NULL AND id IS NOT NULL'; END IF; END $$; CREATE UNIQUE INDEX IF NOT EXISTS idx_schema_migrations_version_p0 ON schema_migrations(version);` + "\n")
	b.WriteString("DO $$ BEGIN IF EXISTS(SELECT 1 FROM schema_migrations WHERE version IS NOT NULL AND version NOT IN (" + knownVersionsSQL(ms) + ")) THEN RAISE EXCEPTION 'database contains migrations unknown to this binary; refusing downgrade/apply'; END IF; END $$;\n")
	for i, m := range ms {
		varName := fmt.Sprintf("applied_%d", i)
		b.WriteString("DO $$ BEGIN IF EXISTS(SELECT 1 FROM schema_migrations WHERE version=" + sqlLiteral(m.Version) + " AND checksum<>'' AND checksum<>" + sqlLiteral(m.Checksum) + ") THEN RAISE EXCEPTION 'migration checksum mismatch: " + m.Version + "'; END IF; END $$;\n")
		b.WriteString("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=" + sqlLiteral(m.Version) + ") AS " + varName + " \\gset\n")
		b.WriteString("\\if :" + varName + "\n")
		b.WriteString("UPDATE schema_migrations SET checksum=" + sqlLiteral(m.Checksum) + ", description=CASE WHEN description='' THEN " + sqlLiteral(m.Version) + " ELSE description END WHERE version=" + sqlLiteral(m.Version) + " AND checksum='';\n")
		b.WriteString("\\echo already-applied " + m.Version + "\n\\else\nBEGIN;\n")
		b.WriteString(m.SQL)
		if !strings.HasSuffix(strings.TrimSpace(m.SQL), ";") {
			b.WriteString(";")
		}
		b.WriteString("\n")
		record := "DO $$ BEGIN IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migrations' AND column_name='id') THEN EXECUTE format('INSERT INTO schema_migrations(id,version,checksum,description) VALUES(%L,%L,%L,%L) ON CONFLICT DO NOTHING', " + sqlLiteral(m.Version) + ", " + sqlLiteral(m.Version) + ", " + sqlLiteral(m.Checksum) + ", " + sqlLiteral(m.Version) + "); ELSE INSERT INTO schema_migrations(version,checksum,description) VALUES(" + sqlLiteral(m.Version) + "," + sqlLiteral(m.Checksum) + "," + sqlLiteral(m.Version) + ") ON CONFLICT(version) DO UPDATE SET checksum=EXCLUDED.checksum,description=EXCLUDED.description; END IF; END $$;"
		b.WriteString(record + "\nCOMMIT;\n\\echo applied " + m.Version + "\n\\endif\n")
	}
	b.WriteString("SELECT pg_advisory_unlock(718033100100);\n")
	return b.String(), nil
}

func BuildVerifyScript() (string, error) {
	ms, err := List()
	if err != nil {
		return "", err
	}
	if len(ms) == 0 {
		return "", fmt.Errorf("migration catalog is empty")
	}
	var b strings.Builder
	b.WriteString("\\set ON_ERROR_STOP on\n")
	b.WriteString("DO $$ BEGIN IF to_regclass(current_schema() || '.schema_migrations') IS NULL THEN RAISE EXCEPTION 'schema_migrations table is missing'; END IF; END $$;\n")
	b.WriteString("CREATE TEMP TABLE nl_expected_migrations(version TEXT PRIMARY KEY, checksum TEXT NOT NULL) ON COMMIT PRESERVE ROWS;\n")
	b.WriteString("INSERT INTO nl_expected_migrations(version,checksum) VALUES " + expectedValuesSQL(ms) + ";\n")
	b.WriteString(`DO $$ DECLARE broken BIGINT; BEGIN
SELECT count(*) INTO broken FROM schema_migrations s LEFT JOIN nl_expected_migrations e ON e.version=s.version WHERE s.version IS NOT NULL AND e.version IS NULL;
IF broken<>0 THEN RAISE EXCEPTION 'database contains % migration(s) unknown to this binary', broken; END IF;
SELECT count(*) INTO broken FROM nl_expected_migrations e LEFT JOIN schema_migrations s ON s.version=e.version WHERE s.version IS NULL;
IF broken<>0 THEN RAISE EXCEPTION 'database has % pending migration(s)', broken; END IF;
SELECT count(*) INTO broken FROM schema_migrations s JOIN nl_expected_migrations e ON e.version=s.version WHERE coalesce(s.checksum,'')='';
IF broken<>0 THEN RAISE EXCEPTION 'database has % migration(s) without sealed checksum', broken; END IF;
SELECT count(*) INTO broken FROM schema_migrations s JOIN nl_expected_migrations e ON e.version=s.version WHERE s.checksum<>e.checksum;
IF broken<>0 THEN RAISE EXCEPTION 'database has % migration checksum mismatch(es)', broken; END IF;
END $$;
`)
	b.WriteString("SELECT 'verified' AS status, count(*) AS migrations, max(version) AS current FROM nl_expected_migrations;\n")
	return b.String(), nil
}

func runPSQL(ctx context.Context, psqlPath, dsn, script, action string) (string, error) {
	if strings.TrimSpace(dsn) == "" {
		return "", fmt.Errorf("PostgreSQL DSN обязателен: --dsn или NEVERLAUNCHER_DATABASE_DSN")
	}
	if strings.TrimSpace(psqlPath) == "" {
		psqlPath = "psql"
	}
	cmd := exec.CommandContext(ctx, psqlPath, "-X", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", dsn)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("psql migration %s failed: %w: %s", action, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func ApplyWithPSQL(ctx context.Context, psqlPath, dsn string) (string, error) {
	script, err := BuildApplyScript()
	if err != nil {
		return "", err
	}
	return runPSQL(ctx, psqlPath, dsn, script, "apply")
}

func VerifyWithPSQL(ctx context.Context, psqlPath, dsn string) (string, error) {
	script, err := BuildVerifyScript()
	if err != nil {
		return "", err
	}
	return runPSQL(ctx, psqlPath, dsn, script, "verification")
}
