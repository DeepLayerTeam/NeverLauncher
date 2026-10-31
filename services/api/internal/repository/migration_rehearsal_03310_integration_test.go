//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMigrationRehearsal03310(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, e := r.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("mig03310-%d", time.Now().UnixNano())
	if _, e := r.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	var runID string
	defer func() {
		c := context.Background()
		for _, q := range []string{
			`DELETE FROM migration_rehearsals_03310 WHERE run_id=$1`,
			`DELETE FROM migration_content_0337 WHERE run_id=$1`,
			`DELETE FROM build_workspaces_0226 WHERE id=$1`,
			`DELETE FROM migration_modules_0338 WHERE run_id=$1`,
			`DELETE FROM migration_security_resets_0336 WHERE run_id=$1`,
			`DELETE FROM migration_auth_imports_0335 WHERE run_id=$1`,
			`DELETE FROM migration_identity_rows_0334 WHERE run_id=$1`,
			`DELETE FROM migration_identity_snapshots_0334 WHERE run_id=$1`,
			`DELETE FROM migration_source_inventory_0333 WHERE run_id=$1`,
			`DELETE FROM migration_events_0331 WHERE run_id=$1`,
			`DELETE FROM migration_runs_0331 WHERE id=$1`,
		} {
			value := runID
			if strings.Contains(q, "build_workspaces") {
				value = project + "-ws"
			}
			if _, e := r.db.ExecContext(c, q, value); e != nil {
				t.Log("cleanup:", e)
			}
		}
		_, _ = r.db.ExecContext(c, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := r.CreateMigration0331(ctx, project, "gravit", "rehearsal-idempotency-key")
	if e != nil {
		t.Fatal(e)
	}
	runID = run.ID
	h := strings.Repeat("a", 64)
	p := gr.Player{SourceID: "fileauth:42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, Economy: "100.00", SkinSHA256: h, Admin: true}
	snap := gr.Snapshot{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []gr.Player{p}}
	signature, _ := gr.SnapshotDigest(snap)
	report := gr.Report{Format: gr.Format, RunID: runID, StageID: "stage_abcdefgh12345678", SourceInventorySHA256: h, SourceSnapshotSHA256: signature, TargetSnapshotSHA256: signature, Source: snap, Target: snap}
	for _, name := range gr.RequiredProbes {
		report.Probes = append(report.Probes, gr.Probe{Name: name, Passed: true, RunID: runID, StageID: report.StageID, UUID: p.UUID, EvidenceSHA256: h})
	}
	if _, e = r.SaveMigrationRehearsal03310(ctx, runID, report); !errors.Is(e, mw.ErrBusy) {
		t.Fatalf("premature staging pass: %v", e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := r.ClaimMigration0331(ctx, runID, "rehearsal-worker", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.CheckpointMigration0331(ctx, lease, step, []byte(`{"verified":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	// Insert durable prerequisite receipts used by MIG03–MIG08. This fixture
	// tests the independent MIG10 relational checks, not an import implementation.
	q := func(sql string, args ...any) {
		t.Helper()
		if _, e := r.db.ExecContext(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	q(`INSERT INTO migration_source_inventory_0333(run_id,source_sha256,manifest_sha256,inventory) VALUES($1,$2,$2,'{}'::jsonb)`, runID, h)
	q(`INSERT INTO migration_identity_snapshots_0334(run_id,source_sha256,inventory_sha256,entries_sha256) VALUES($1,$2,$2,$2)`, runID, h)
	q(`INSERT INTO migration_identity_rows_0334(run_id,ordinal,provider,source_id,username,minecraft_uuid,source_path,status,reason) VALUES($1,0,'fileauth','42','TestPlayer',$2,'Database.json','pending_import','test')`, runID, p.UUID)
	q(`INSERT INTO migration_auth_imports_0335(run_id,source_sha256,identity_sha256,decision_sha256,report) VALUES($1,$2,$2,$2,'{}'::jsonb)`, runID, h)
	q(`INSERT INTO migration_security_resets_0336(run_id,auth_decision_sha256,active_jwt_kid,manifest_public_sha256,report) VALUES($1,$2,'fresh-key',$2,'{}'::jsonb)`, runID, h)
	q(`INSERT INTO build_workspaces_0226(id,project_id,owner_id,revision,data) VALUES($1,$2,'operator',1,'{"state":"staged","files":[{"path":"assets/snapshot.dat","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"ownership":"required"}]}'::jsonb)`, project+"-ws", project)
	q(`INSERT INTO migration_content_0337(run_id,profile_path,source_sha256,manifest_sha256,files_sha256,profile_id,workspace_id,owner_id,report) VALUES($1,'profiles/client.json',$2,$2,$2,'client',$3,'operator','{"files":[{"targetPath":"assets/snapshot.dat","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"ownership":"required"}]}'::jsonb)`, runID, h, project+"-ws")
	if _, e = r.SaveMigrationRehearsal03310(ctx, runID, report); e == nil {
		t.Fatal("missing MIG08 review passed")
	}
	modules := gm.Report{Format: gm.Format, SourceSHA256: h, InventorySHA256: h, Ready: true, Blockers: []string{}, Modules: []gm.Module{}, Wrappers: []gm.Wrapper{}}
	if _, e = r.SaveMigrationModules0338(ctx, runID, modules); e != nil {
		t.Fatal(e)
	}
	saved, e := r.SaveMigrationRehearsal03310(ctx, runID, report)
	if e != nil || !saved.Ready || saved.CutoverAllowed {
		t.Fatalf("good stage: %+v %v", saved, e)
	}
	before, e := r.GetMigration0331(ctx, runID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.SaveMigrationRehearsal03310(ctx, runID, report); e != nil {
		t.Fatal("retry:", e)
	}
	after, e := r.GetMigration0331(ctx, runID)
	if e != nil || before.Revision != after.Revision {
		t.Fatalf("duplicate event %v", e)
	}
	report.Probes[0].Passed = false
	if _, e = r.SaveMigrationRehearsal03310(ctx, runID, report); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed stage accepted: %v", e)
	}
	report.StageID = "stage_different12345678"
	for i := range report.Probes {
		report.Probes[i].StageID = report.StageID
	}
	blocked, e := r.SaveMigrationRehearsal03310(ctx, runID, report)
	if e != nil || blocked.Ready {
		t.Fatalf("failed second stage: %+v %v", blocked, e)
	}
}
