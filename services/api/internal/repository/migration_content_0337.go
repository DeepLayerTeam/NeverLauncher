package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// EnsureMigrationContent0337 makes the profile/workspace reservation durable
// before object staging. A network interruption returns to precisely the same
// profile/workspace; it never silently adopts an unrelated existing profile.
func (r *SQLRepository) EnsureMigrationContent0337(ctx context.Context, runID, owner, channel, version string, plan gc.Plan) (BuildWorkspace, error) {
	if e := r.check(); e != nil {
		return BuildWorkspace{}, e
	}
	if !plan.Ready || len(plan.Files) == 0 || len(plan.Files) > gc.MaxImportFiles || plan.FilesSHA256 == "" || owner == "" {
		return BuildWorkspace{}, mw.ErrConflict
	}
	if len(channel) > 128 || len(version) > 128 || channel == "" || version == "" || strings.ContainsAny(channel+version, "/\\\x00\r\n") {
		return BuildWorkspace{}, errors.New("invalid destination release channel/version")
	}
	profile := plan.Profile.Profile
	if profile.Revision != 0 || profile.ID == "" { // converter yields normalized revision zero
		return BuildWorkspace{}, mw.ErrConflict
	}
	ws := BuildWorkspace{
		ID: migrationContentWorkspaceID0337(runID, plan.ProfilePath), ProjectID: profile.ProjectID, OwnerID: owner, ProfileID: profile.ID,
		Channel: channel, Version: version, Settings: BuildSettings{Minecraft: plan.Profile.Settings.Minecraft, Runtime: plan.Profile.Settings.Runtime, Directories: plan.Profile.Settings.Directories, FileRules: plan.Profile.Settings.FileRules,
			ToolVersions: map[string]string{"gravit-content-migration": "0.33.7"}}, Files: []BuildFile{},
	}
	profile, ws, e := prepareGravitImport02210(profile, ws)
	if e != nil {
		return BuildWorkspace{}, e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return BuildWorkspace{}, e
	}
	defer tx.Rollback()
	var kind, status, step, project string
	e = tx.QueryRowContext(ctx, `SELECT source_kind,status,step,project_id FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, runID).Scan(&kind, &status, &step, &project)
	if errors.Is(e, sql.ErrNoRows) {
		return BuildWorkspace{}, mw.ErrNotFound
	}
	if e != nil {
		return BuildWorkspace{}, e
	}
	if kind != "gravit" || status != "prepared" || step != "source_assessment" || project != profile.ProjectID {
		return BuildWorkspace{}, mw.ErrBusy
	}
	var invSource, invManifest string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, runID).Scan(&invSource, &invManifest)
	if e != nil {
		return BuildWorkspace{}, e
	}
	if invSource != plan.SourceSHA256 || invManifest != plan.InventorySHA256 {
		return BuildWorkspace{}, mw.ErrConflict
	}
	// Bind the migrated content to MIG04's approved source identity whenever
	// MIG04 exists; content import itself does not grant login or permissions.
	var oldSource, oldManifest, oldFiles, oldProfile, oldWorkspace, oldOwner string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256,files_sha256,profile_id,workspace_id,owner_id FROM migration_content_0337 WHERE run_id=$1 AND profile_path=$2`, runID, plan.ProfilePath).Scan(&oldSource, &oldManifest, &oldFiles, &oldProfile, &oldWorkspace, &oldOwner)
	if e == nil {
		if oldSource != invSource || oldManifest != invManifest || oldFiles != plan.FilesSHA256 || oldProfile != profile.ID || oldWorkspace != ws.ID || oldOwner != owner {
			return BuildWorkspace{}, mw.ErrConflict
		}
		var stored BuildWorkspace
		b := []byte{}
		if e = tx.QueryRowContext(ctx, `SELECT data FROM build_workspaces_0226 WHERE id=$1`, ws.ID).Scan(&b); e != nil {
			return BuildWorkspace{}, e
		}
		if e = json.Unmarshal(b, &stored); e != nil {
			return BuildWorkspace{}, e
		}
		if stored.ProfileDigest != ws.ProfileDigest || stored.ProjectID != ws.ProjectID || stored.OwnerID != owner || stored.Channel != channel || stored.Version != version {
			return BuildWorkspace{}, mw.ErrConflict
		}
		if e = tx.Commit(); e != nil {
			return BuildWorkspace{}, e
		}
		return stored, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return BuildWorkspace{}, e
	}
	now := time.Now().UTC()
	profile.Revision, profile.CreatedAt, profile.UpdatedAt = 1, now, now
	res, e := tx.ExecContext(ctx, `INSERT INTO profiles(id,project_id,name,description,loader,preset,is_default,created_at,updated_at,schema_version,revision,digest) VALUES($1,$2,$3,$4,$5,$6,false,$7,$7,'2.0',1,$8) ON CONFLICT (project_id,id) DO NOTHING`, profile.ID, profile.ProjectID, profile.Name, profile.Description, profile.Loader, profile.Preset, now, profile.Digest)
	if e != nil {
		return BuildWorkspace{}, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return BuildWorkspace{}, e
	}
	if n != 1 {
		return BuildWorkspace{}, mw.ErrConflict
	}
	snap := model.SnapshotProfile(profile)
	raw, e := json.Marshal(snap.Spec)
	if e != nil {
		return BuildWorkspace{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO profile_revisions_0221(project_id,profile_id,revision,schema_version,digest,spec,created_at) VALUES($1,$2,1,'2.0',$3,$4::jsonb,$5)`, profile.ProjectID, profile.ID, snap.Digest, string(raw), now); e != nil {
		return BuildWorkspace{}, e
	}
	ws.Revision, ws.State, ws.CreatedAt, ws.UpdatedAt = 1, "importing", now, now
	b, e := json.Marshal(ws)
	if e != nil {
		return BuildWorkspace{}, e
	}
	res, e = tx.ExecContext(ctx, `INSERT INTO build_workspaces_0226(id,project_id,owner_id,revision,data) VALUES($1,$2,$3,1,$4::jsonb) ON CONFLICT DO NOTHING`, ws.ID, ws.ProjectID, ws.OwnerID, string(b))
	if e != nil {
		return BuildWorkspace{}, e
	}
	n, e = res.RowsAffected()
	if e != nil {
		return BuildWorkspace{}, e
	}
	if n != 1 {
		return BuildWorkspace{}, mw.ErrConflict
	}
	receipt, e := json.Marshal(plan)
	if e != nil {
		return BuildWorkspace{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO migration_content_0337(run_id,profile_path,source_sha256,manifest_sha256,files_sha256,profile_id,workspace_id,owner_id,report) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, runID, plan.ProfilePath, plan.SourceSHA256, plan.InventorySHA256, plan.FilesSHA256, profile.ID, ws.ID, owner, string(receipt)); e != nil {
		return BuildWorkspace{}, e
	}
	if e = tx.Commit(); e != nil {
		return BuildWorkspace{}, fmt.Errorf("commit migration profile/workspace: %w", e)
	}
	return ws, nil
}

func migrationContentWorkspaceID0337(run, profilePath string) string {
	return gc.WorkspaceID(run, profilePath)
}

func (r *SQLRepository) GetMigrationContent0337(ctx context.Context, runID, profilePath string) (gc.Plan, BuildWorkspace, error) {
	if e := r.check(); e != nil {
		return gc.Plan{}, BuildWorkspace{}, e
	}
	var raw []byte
	var workspaceID string
	e := r.db.QueryRowContext(ctx, `SELECT report,workspace_id FROM migration_content_0337 WHERE run_id=$1 AND profile_path=$2`, runID, profilePath).Scan(&raw, &workspaceID)
	if errors.Is(e, sql.ErrNoRows) {
		return gc.Plan{}, BuildWorkspace{}, mw.ErrNotFound
	}
	if e != nil {
		return gc.Plan{}, BuildWorkspace{}, e
	}
	var plan gc.Plan
	if e = json.Unmarshal(raw, &plan); e != nil {
		return gc.Plan{}, BuildWorkspace{}, e
	}
	ws, e := r.GetBuildWorkspace(ctx, workspaceID)
	return plan, ws, e
}
