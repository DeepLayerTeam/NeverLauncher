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

func BuildApplyScript() (string, error) {
	ms, err := List()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("\\set ON_ERROR_STOP on\nSELECT pg_advisory_lock(718033100100);\n")
	b.WriteString(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, checksum TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', applied_at TIMESTAMPTZ NOT NULL DEFAULT now());` + "\n")
	b.WriteString(`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS version TEXT; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT ''; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''; ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ NOT NULL DEFAULT now();` + "\n")
	b.WriteString(`DO $$ BEGIN IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migrations' AND column_name='id') THEN EXECUTE 'UPDATE schema_migrations SET version=id WHERE version IS NULL AND id IS NOT NULL'; END IF; END $$; CREATE UNIQUE INDEX IF NOT EXISTS idx_schema_migrations_version_p0 ON schema_migrations(version);` + "\n")
	for i, m := range ms {
		varName := fmt.Sprintf("applied_%d", i)
		b.WriteString("DO $$ BEGIN IF EXISTS(SELECT 1 FROM schema_migrations WHERE version=" + sqlLiteral(m.Version) + " AND checksum<>'' AND checksum<>" + sqlLiteral(m.Checksum) + ") THEN RAISE EXCEPTION 'migration checksum mismatch: " + m.Version + "'; END IF; END $$;\n")
		b.WriteString("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=" + sqlLiteral(m.Version) + ") AS " + varName + " \\gset\n")
		b.WriteString("\\if :" + varName + "\n\\echo already-applied " + m.Version + "\n\\else\nBEGIN;\n")
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

func ApplyWithPSQL(ctx context.Context, psqlPath, dsn string) (string, error) {
	if strings.TrimSpace(dsn) == "" {
		return "", fmt.Errorf("PostgreSQL DSN обязателен: --dsn или NEVERLAUNCHER_DATABASE_DSN")
	}
	if strings.TrimSpace(psqlPath) == "" {
		psqlPath = "psql"
	}
	script, err := BuildApplyScript()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, psqlPath, "-X", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--dbname", dsn)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("psql migration failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
