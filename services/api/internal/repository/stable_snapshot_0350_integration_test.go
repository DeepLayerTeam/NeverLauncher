//go:build !launcher_nopgx

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// This test executes actual PostgreSQL triggers and assertions; it does not
// substitute mocks for the protected release tables.
func TestGAStableSnapshotImmutablePostgres0350(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := repo.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	project := fmt.Sprintf("ga-0350-%d", time.Now().UnixNano())
	stable := project + "-stable"
	dev := project + "-dev"
	for _, statement := range []string{
		`INSERT INTO projects(id,name) VALUES($1,$1)`,
		`INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($2,$1,'vanilla','stable','0.35.0','integrity-passed','{}'::jsonb)`,
		`INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($3,$1,'vanilla','dev','0.35.0','integrity-passed','{}'::jsonb)`,
		`INSERT INTO files(id,project_id,version_id,path,size,sha256,url,required) VALUES($1||'-f',$1,$2,'client.jar',4,$4,'',true)`,
		`INSERT INTO package_integrity_checks(id,package_id,project_id,manifest_digest,artifact_digest,signature_verified,storage_verified,files_verified,compatibility_verified,result) VALUES($1||'-check',$2,$1,$4,$4,true,true,true,true,'passed')`,
	} {
		params := []any{project, stable, dev, strings.Repeat("a", 64)}
		for len(params) > 1 && !strings.Contains(statement, fmt.Sprintf("$%d", len(params))) {
			params = params[:len(params)-1]
		}
		if _, err = tx.ExecContext(ctx, statement, params...); err != nil {
			t.Fatalf("fixture: %s: %v", statement, err)
		}
	}
	blocked := map[string]string{
		"alter signed file":            `UPDATE files SET sha256=$2 WHERE version_id=$1`,
		"delete signed file":           `DELETE FROM files WHERE version_id=$1`,
		"append signed file":           `INSERT INTO files(id,project_id,version_id,path,size,sha256,url,required) SELECT id||'-new',project_id,version_id,'extra.jar',4,$2,'',true FROM files WHERE version_id=$1`,
		"alter signed manifest":        `UPDATE release_versions SET manifest='{"a":1}'::jsonb WHERE id=$1`,
		"overwrite verified integrity": `UPDATE package_integrity_checks SET result='failed' WHERE package_id=$1`,
		"delete verified release":      `DELETE FROM release_versions WHERE id=$1`,
		"manual publish":               `UPDATE release_versions SET status='published' WHERE id=$1`,
		"direct stable head":           `INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest) SELECT project_id,profile_id,'stable',1,id,version,$2 FROM release_versions WHERE id=$1`,
	}
	for name, query := range blocked {
		t.Run(name, func(t *testing.T) {
			if _, e := tx.ExecContext(ctx, "SAVEPOINT ga_negative"); e != nil {
				t.Fatal(e)
			}
			args := []any{stable}
			if strings.Contains(query, "$2") {
				args = append(args, strings.Repeat("b", 64))
			}
			_, e := tx.ExecContext(ctx, query, args...)
			if e == nil || !strings.Contains(e.Error(), "stable_runtime_gate_") {
				t.Errorf("bypass should fail with gate diagnostic: %v", e)
			}
			if _, rollback := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT ga_negative"); rollback != nil {
				t.Fatal(rollback)
			}
			if _, release := tx.ExecContext(ctx, "RELEASE SAVEPOINT ga_negative"); release != nil {
				t.Fatal(release)
			}
		})
	}
	// A less strict policy on dev remains available; stable freeze must not
	// globally make normal development files read-only.
	if _, err = tx.ExecContext(ctx, `UPDATE release_versions SET manifest='{"test":true}'::jsonb WHERE id=$1`, dev); err != nil {
		t.Fatalf("dev unexpectedly frozen: %v", err)
	}
}
