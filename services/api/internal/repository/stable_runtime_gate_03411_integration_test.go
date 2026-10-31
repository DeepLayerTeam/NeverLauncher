//go:build !launcher_nopgx

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestV11StableSQLRejectsForgedPermitAndManualWrites03411(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, err := repo.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("stable-03411-%d", time.Now().UnixNano())
	id := project + "-release"
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.db.Exec(`DELETE FROM stable_runtime_permits_03411 WHERE project_id=$1`, project)
		_, _ = repo.db.Exec(`DELETE FROM release_versions WHERE project_id=$1`, project)
		_, _ = repo.db.Exec(`DELETE FROM projects WHERE id=$1`, project)
	}()
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($1,$2,'vanilla','stable','0.34.11','draft','{}'::jsonb)`, id, project); err != nil {
		t.Fatal(err)
	}
	target, _ := json.Marshal([]map[string]string{{"id": "linux-amd64", "projectId": project, "version": "0.34.11"}})
	token, err := repo.IssueStableRuntimePermit03411(ctx, StableRuntimePermit03411{
		PackageID: id, ProjectID: project, ManifestSHA256: strings.Repeat("a", 64), ArtifactSHA256: strings.Repeat("b", 64), MatrixSHA256: strings.Repeat("c", 64), TargetsJSON: target, Runs: map[string]string{"linux-amd64": "forged-run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for label, withToken := range map[string]bool{"no-token": false, "fake-grant-but-no-attestations": true} {
		t.Run(label, func(t *testing.T) {
			tx, e := repo.db.BeginTx(ctx, &sql.TxOptions{})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if withToken {
				if _, e = tx.ExecContext(ctx, `SELECT set_config('stable_gate_token',$1,true)`, token); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = tx.ExecContext(ctx, `UPDATE release_versions SET status='published' WHERE id=$1`, id); e == nil || !strings.Contains(e.Error(), "stable_runtime_gate_03411") {
				t.Fatalf("manual published status bypass: %v", e)
			}
		})
	}
	tx, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('stable_gate_token',$1,true)`, token); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest) VALUES($1,'vanilla','stable',1,$2,'0.34.11',$3)`, project, id, strings.Repeat("a", 64))
	if err == nil || !strings.Contains(err.Error(), "stable_runtime_gate_03411") {
		t.Fatalf("forged grant changed stable head: %v", err)
	}
}
