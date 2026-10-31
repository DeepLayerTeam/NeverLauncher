//go:build !launcher_nopgx

package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	co "gitflic.ru/skif4er/launcher/services/api/internal/gravitcutover"
	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	rb "gitflic.ru/skif4er/launcher/services/api/internal/gravitrollback"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestMigrationCutoverPostgres03311(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, e := r.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	project := fmt.Sprintf("mig03311-%d", time.Now().UnixNano())
	const profile = "client"
	const channel = "dev"
	const player = "12345678-1234-1234-1234-123456789abc"
	user := project + "-player"
	wsID := project + "-ws"
	targetID := project + "-new"
	oldID := project + "-old"
	var runID string
	defer func() {
		c := context.Background()
		clean := func(q string, args ...any) {
			if _, e := r.db.ExecContext(c, q, args...); e != nil {
				t.Log("cleanup", e)
			}
		}
		clean(`DELETE FROM migration_rollbacks_03312 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_cutovers_03311 WHERE run_id=$1`, runID)
		clean(`DELETE FROM channel_heads WHERE project_id=$1`, project)
		clean(`DELETE FROM migration_rehearsals_03310 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_content_0337 WHERE run_id=$1`, runID)
		clean(`DELETE FROM build_workspaces_0226 WHERE id=$1`, wsID)
		clean(`DELETE FROM migration_modules_0338 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_security_resets_0336 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_security_targets_0336 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_auth_imports_0335 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_identity_rows_0334 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_identity_snapshots_0334 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_source_inventory_0333 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_events_0331 WHERE run_id=$1`, runID)
		clean(`DELETE FROM migration_runs_0331 WHERE id=$1`, runID)
		clean(`DELETE FROM minecraft_profiles WHERE user_id=$1`, user)
		clean(`DELETE FROM users WHERE id=$1`, user)
		clean(`DELETE FROM release_versions WHERE project_id=$1`, project)
		clean(`DELETE FROM projects WHERE id=$1`, project)
	}()
	q := func(sql string, args ...any) {
		t.Helper()
		if _, e := r.db.ExecContext(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	q(`INSERT INTO projects(id,name) VALUES($1,$1)`, project)
	run, e := r.CreateMigration0331(ctx, project, "gravit", "cutover-idempotency-key")
	if e != nil {
		t.Fatal(e)
	}
	runID = run.ID
	q(`UPDATE migration_runs_0331 SET status='prepared',step='source_assessment' WHERE id=$1`, runID)
	hash := strings.Repeat("a", 64)
	q(`INSERT INTO migration_source_inventory_0333(run_id,source_sha256,manifest_sha256,inventory) VALUES($1,$2,$2,'{}'::jsonb)`, runID, hash)
	q(`INSERT INTO users(id,email,display_name,role_id,status,project_roles,password_hash,created_at,updated_at) VALUES($1,$2,'TestPlayer','player','active','{}'::jsonb,'test',now(),now())`, user, project+"@example.test")
	q(`INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at) VALUES($1,$2,'TestPlayer','launcher','local',$2,'gravit-import-v1',now(),now())`, user, player)
	q(`INSERT INTO migration_identity_snapshots_0334(run_id,source_sha256,inventory_sha256,entries_sha256) VALUES($1,$2,$2,$2)`, runID, hash)
	q(`INSERT INTO migration_identity_rows_0334(run_id,ordinal,provider,source_id,username,minecraft_uuid,source_path,status,reason) VALUES($1,0,'fileauth','42','TestPlayer',$2,'Database.json','pending_import','test')`, runID, player)
	q(`INSERT INTO migration_auth_imports_0335(run_id,source_sha256,identity_sha256,decision_sha256,report) VALUES($1,$2,$2,$2,'{"manualReset":0,"dryRun":false,"rows":[{"state":"imported"}]}'::jsonb)`, runID, hash)
	q(`INSERT INTO migration_security_targets_0336(run_id,user_id,expected_name,expected_uuid) VALUES($1,$2,'TestPlayer',$3)`, runID, user, player)
	q(`INSERT INTO migration_security_resets_0336(run_id,auth_decision_sha256,active_jwt_kid,manifest_public_sha256,report) VALUES($1,$2,'new-key',$2,'{"verified":true}'::jsonb)`, runID, hash)
	q(`INSERT INTO migration_modules_0338(run_id,source_sha256,inventory_sha256,report) VALUES($1,$2,$2,'{"ready":true,"blockers":[]}'::jsonb)`, runID, hash)
	q(`INSERT INTO build_workspaces_0226(id,project_id,owner_id,revision,data) VALUES($1,$2,'operator',1,$3::jsonb)`, wsID, project, fmt.Sprintf(`{"packageId":%q,"state":"built","files":[]}`, targetID))
	q(`INSERT INTO migration_content_0337(run_id,profile_path,source_sha256,manifest_sha256,files_sha256,profile_id,workspace_id,owner_id,report) VALUES($1,'profiles/client.json',$2,$2,$2,$3,$4,'operator','{"files":[]}'::jsonb)`, runID, hash, profile, wsID)
	snap := gr.Snapshot{WorldSHA256: hash, Loader: "forge", OptionalPresetSHA256: hash, Players: []gr.Player{{SourceID: "fileauth:42", UUID: player, InventorySHA256: hash, PermissionsSHA256: hash, SkinSHA256: hash, Economy: "100", Admin: true}}}
	snapHash, _ := gr.SnapshotDigest(snap)
	rep := gr.Report{Format: gr.Format, RunID: runID, StageID: "stage_abcdefgh12345678", SourceInventorySHA256: hash, SourceSnapshotSHA256: snapHash, TargetSnapshotSHA256: snapHash, Source: snap, Target: snap}
	for _, name := range gr.RequiredProbes {
		rep.Probes = append(rep.Probes, gr.Probe{Name: name, Passed: true, RunID: runID, StageID: rep.StageID, UUID: player, EvidenceSHA256: hash})
	}
	if _, e = r.SaveMigrationRehearsal03310(ctx, runID, rep); e != nil {
		t.Fatal("rehearsal", e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := model.Manifest{SchemaVersion: "1.0", ProjectID: project, ProfileID: profile, Channel: channel, Version: "never-v2", Files: []model.ManifestFile{}}
	bare, _ := json.Marshal(m)
	m.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Signature: hex.EncodeToString(ed25519.Sign(priv, bare))}
	raw, _ := json.Marshal(m)
	q(`INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($1,$2,$3,$4,$5,'published',$6::jsonb)`, targetID, project, profile, channel, m.Version, string(raw))
	oldManifest := model.Manifest{SchemaVersion: "1.0", ProjectID: project, ProfileID: profile, Channel: channel, Version: "old", Files: []model.ManifestFile{}}
	oldUnsigned, _ := json.Marshal(oldManifest)
	oldManifest.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Signature: hex.EncodeToString(ed25519.Sign(priv, oldUnsigned))}
	oldRaw, _ := json.Marshal(oldManifest)
	oldHash := sha256.Sum256(oldRaw)
	oldDigest := hex.EncodeToString(oldHash[:])
	q(`INSERT INTO release_versions(id,project_id,profile_id,channel,version,status,manifest) VALUES($1,$2,$3,$4,'old','published',$5::jsonb)`, oldID, project, profile, channel, string(oldRaw))
	q(`INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest) VALUES($1,$2,$3,8,$4,'old',$5)`, project, profile, channel, oldID, oldDigest)
	stage := co.Stage{ProfileID: profile, Channel: channel, ReleaseID: targetID, StageID: rep.StageID, ExpectedHeadRevision: 8}
	if _, e = r.StageMigrationCutover03311(ctx, runID, co.Stage{ProfileID: profile, Channel: channel, ReleaseID: targetID, StageID: rep.StageID, ExpectedHeadRevision: 7}, pub); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("stale head accepted: %v", e)
	}
	route, e := r.StageMigrationCutover03311(ctx, runID, stage, pub)
	if e != nil || route.State != "staged" {
		t.Fatalf("stage: %+v %v", route, e)
	}
	again, e := r.StageMigrationCutover03311(ctx, runID, stage, pub)
	if e != nil || again.Revision != route.Revision {
		t.Fatalf("stage replay %+v %v", again, e)
	}
	if _, e = r.db.ExecContext(ctx, `UPDATE channel_heads SET revision=9 WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, project, profile, channel); e == nil {
		t.Fatal("concurrent publisher escaped staged DB trigger")
	}
	activation := co.Activate{ProfileID: profile, Channel: channel, ExpectedRevision: route.Revision, SourceFenceReference: "ops/fence-ticket-42", SourceFenceEvidenceSHA256: hash, CurrentSourceSnapshotSHA256: hash}
	if _, e = r.ActivateMigrationCutover03311(ctx, runID, activation, pub); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("wrong source snapshot accepted: %v", e)
	}
	activation.CurrentSourceSnapshotSHA256 = snapHash
	active, e := r.ActivateMigrationCutover03311(ctx, runID, activation, pub)
	if e != nil || active.State != "active" || active.ActivatedRevision == nil || *active.ActivatedRevision != 9 {
		t.Fatalf("activate: %+v %v", active, e)
	}
	again, e = r.ActivateMigrationCutover03311(ctx, runID, activation, pub)
	if e != nil || again.Revision != active.Revision {
		t.Fatalf("replay: %+v %v", again, e)
	}
	var head string
	var rev int64
	if e = r.db.QueryRowContext(ctx, `SELECT release_id,revision FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, project, profile, channel).Scan(&head, &rev); e != nil || head != targetID || rev != 9 {
		t.Fatalf("channel not switched: %s %d %v", head, rev, e)
	}
	if _, e = r.CancelMigrationCutover03311(ctx, runID, profile, channel, active.Revision); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("post-cutover cancel accepted: %v", e)
	}
	// MIG12 must fence the *active* route as well (and guard DELETE).
	if _, e = r.db.ExecContext(ctx, `UPDATE channel_heads SET version='unapproved' WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, project, profile, channel); e == nil {
		t.Fatal("active head accepted another publisher")
	}
	if _, e = r.db.ExecContext(ctx, `DELETE FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, project, profile, channel); e == nil {
		t.Fatal("active head delete bypassed guard")
	}
	planInput := rb.PlanInput{ProfileID: profile, Channel: channel, ExpectedRevision: active.Revision, Current: rep.Target, EvidenceReference: "runbooks/frozen-export-0001", EvidenceSHA256: hash}
	mutated := planInput
	mutated.Current.Players = append([]gr.Player(nil), rep.Target.Players...)
	mutated.Current.Players[0].Economy = "101"
	blocked, e := r.PlanMigrationRollback03312(ctx, runID, mutated)
	if e != nil || blocked.Ready || len(blocked.Blockers) == 0 {
		t.Fatalf("changed player data accepted: %+v %v", blocked, e)
	}
	plan, e := r.PlanMigrationRollback03312(ctx, runID, planInput)
	if e != nil || !plan.Ready || plan.State != "planned" {
		t.Fatalf("plan: %+v %v", plan, e)
	}
	againPlan, e := r.PlanMigrationRollback03312(ctx, runID, planInput)
	if e != nil || againPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("idempotent plan: %+v %v", againPlan, e)
	}
	commit := rb.CommitInput{ProfileID: profile, Channel: channel, ExpectedRevision: active.Revision, PlanSHA256: plan.PlanSHA256, Current: rep.Target, CurrentEvidenceSHA256: hash}
	if _, e = r.CommitMigrationRollback03312(ctx, runID, commit, pub); e == nil {
		t.Fatal("unfenced commit accepted")
	}
	commit.SourceWriterFenced = true
	commit.NeverWriterFenced = true
	changed := commit
	changed.Current.Players = append([]gr.Player(nil), commit.Current.Players...)
	changed.Current.Players[0].Economy = "999"
	if _, e = r.CommitMigrationRollback03312(ctx, runID, changed, pub); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("changed snapshot allowed: %v", e)
	}
	result, e := r.CommitMigrationRollback03312(ctx, runID, commit, pub)
	if e != nil || result.State != "completed" {
		t.Fatalf("commit: %+v %v", result, e)
	}
	replay, e := r.CommitMigrationRollback03312(ctx, runID, commit, pub)
	if e != nil || replay.PlanSHA256 != result.PlanSHA256 {
		t.Fatalf("commit replay: %+v %v", replay, e)
	}
	if e = r.db.QueryRowContext(ctx, `SELECT release_id,revision FROM channel_heads WHERE project_id=$1 AND profile_id=$2 AND channel=$3`, project, profile, channel).Scan(&head, &rev); e != nil || head != oldID || rev != 10 {
		t.Fatalf("rollback head incorrect: %s %d %v", head, rev, e)
	}
	if _, e = r.ActivateMigrationCutover03311(ctx, runID, activation, pub); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("reactivation after rollback allowed: %v", e)
	}
}
