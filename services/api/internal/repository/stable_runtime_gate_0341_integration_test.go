//go:build !neverlauncher_nopgx

package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStableSQLTriggersRejectAllHeadAndManualStatusWrites0341(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("stable0341-%d", time.Now().UnixNano())
	releaseID := project + "-release"
	_, err := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM release_versions WHERE project_id=$1`, project)
		_, _ = repo.db.ExecContext(context.Background(), `DELETE FROM projects WHERE id=$1`, project)
	}()
	_, err = repo.db.ExecContext(ctx, `INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($1,$2,'vanilla','stable','1','draft','{}'::jsonb)`, releaseID, project)
	if err != nil {
		t.Fatal(err)
	}
	for label, query := range map[string]string{
		"manual status":                   `UPDATE release_versions SET status='published' WHERE id=$1`,
		"direct head insert":              `INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest) SELECT project_id,profile_id,'stable',1,id,version,'' FROM release_versions WHERE id=$1`,
		"direct already-published insert": `INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) SELECT id||'-x',project_id,profile_id,'stable','2','published','{}'::jsonb FROM release_versions WHERE id=$1`,
	} {
		if _, e := repo.db.ExecContext(ctx, query, releaseID); e == nil || !strings.Contains(e.Error(), "stable_runtime_gate_0341") {
			t.Errorf("%s bypass: %v", label, e)
		}
	}
	// The guard does not affect a different channel.
	if _, err := repo.db.ExecContext(ctx, `UPDATE release_versions SET channel='dev' WHERE id=$1`, releaseID); err == nil {
		t.Fatal("release identity was unexpectedly mutable")
	}
}
