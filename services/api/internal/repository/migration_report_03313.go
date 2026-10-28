package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gc "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcontent"
	cr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcredentials"
	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitmodules"
	gr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitrehearsal"
	rr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitreport"
	mw "gitflic.ru/skif4er/neverlauncher/services/api/internal/migrationworkflow"
)

// migrationEvidence03313 is deliberately a read-only, REPEATABLE READ
// transaction. It does not trust caller-provided source data or report fields.
func migrationEvidence03313(ctx context.Context, tx *sql.Tx, run string) (rr.Report, error) {
	v := rr.Report{RunID: run, Items: []rr.Item{}, Identities: []rr.Identity{}, Evidence: []rr.Evidence{}, Decisions: []rr.Decision{}, Blockers: []string{}}
	var kind string
	if e := tx.QueryRowContext(ctx, `SELECT project_id,source_kind,revision FROM migration_runs_0331 WHERE id=$1`, run).Scan(&v.ProjectID, &kind, &v.RunRevision); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return v, mw.ErrNotFound
		}
		return v, e
	}
	if kind != "gravit" {
		return v, mw.ErrConflict
	}
	add := func(stage, state, digest, details string) {
		v.Evidence = append(v.Evidence, rr.Evidence{Stage: stage, State: state, SHA256: digest, Details: details})
	}
	missing := func(e error) bool { return errors.Is(e, sql.ErrNoRows) }
	var compat []byte
	var compSource string
	e := tx.QueryRowContext(ctx, `SELECT source_sha256,report FROM migration_compatibility_0332 WHERE run_id=$1`, run).Scan(&compSource, &compat)
	if missing(e) {
		add("compatibility", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var c struct {
			VersionStatus string `json:"versionStatus"`
			Status        string `json:"status"`
			Findings      []struct {
				Severity string `json:"severity"`
				Code     string `json:"code"`
			} `json:"findings"`
		}
		if e = json.Unmarshal(compat, &c); e != nil {
			return v, e
		}
		state := "verified"
		if c.VersionStatus != "recognized" {
			state = "blocked"
		}
		if c.Status == "blocked" {
			state = "blocked"
		}
		for _, f := range c.Findings {
			if f.Severity == "blocker" || f.Severity == "error" {
				state = "blocked"
			}
		}
		add("compatibility", state, compSource, "version="+c.VersionStatus)
	}
	var inventory []byte
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256,inventory FROM migration_source_inventory_0333 WHERE run_id=$1`, run).Scan(&v.SourceSHA256, &v.InventorySHA256, &inventory)
	if missing(e) {
		add("inventory", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var i inv.Inventory
		if e = json.Unmarshal(inventory, &i); e != nil {
			return v, e
		}
		if _, e = i.Manifest(); e != nil {
			return v, e
		}
		if i.SourceSHA256 != v.SourceSHA256 || i.ManifestSHA256 != v.InventorySHA256 || compSource != "" && compSource != v.SourceSHA256 {
			v.Blockers = append(v.Blockers, "source digests differ between MIG02 and MIG03")
		}
		if len(i.Files) > 30000 {
			return v, mw.ErrConflict
		}
		for _, f := range i.Files {
			v.Items = append(v.Items, rr.Item{Kind: f.Kind, Source: f.Path, Status: "manual", SHA256: f.SHA256, Reason: "source inventory; destination not yet independently verified"})
		}
		add("inventory", "verified", v.InventorySHA256, fmt.Sprintf("files=%d bytes=%d", len(i.Files), i.TotalBytes))
	}
	// The inventory lists every source object once; later verified transfers
	// replace their manual entry rather than inflating the manual count.
	inventoryItemCount := len(v.Items)
	coveredSources := map[string]bool{}
	var idsHash, idsSource, idsInv string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,inventory_sha256,entries_sha256 FROM migration_identity_snapshots_0334 WHERE run_id=$1`, run).Scan(&idsSource, &idsInv, &idsHash)
	if missing(e) {
		add("identity", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		if idsInv != v.InventorySHA256 || idsSource != v.SourceSHA256 {
			v.Blockers = append(v.Blockers, "MIG04 identity source checksum mismatch")
		}
		rows, qe := tx.QueryContext(ctx, `SELECT i.provider,i.source_id,i.username,i.minecraft_uuid,COALESCE(i.target_user_id,mp.user_id,''),i.status FROM migration_identity_rows_0334 i LEFT JOIN minecraft_profiles mp ON mp.uuid=i.minecraft_uuid WHERE i.run_id=$1 ORDER BY i.ordinal`, run)
		if qe != nil {
			return v, qe
		}
		for rows.Next() {
			var id rr.Identity
			if qe = rows.Scan(&id.Provider, &id.SourceID, &id.Username, &id.UUID, &id.TargetUserID, &id.Status); qe != nil {
				break
			}
			if id.Status == "pending_import" && id.TargetUserID != "" {
				id.Status = "imported"
			}
			v.Identities = append(v.Identities, id)
		}
		if qe == nil {
			qe = rows.Err()
		}
		rows.Close()
		if qe != nil {
			return v, qe
		}
		if len(v.Identities) > 200000 {
			return v, mw.ErrConflict
		}
		add("identity", "verified", idsHash, fmt.Sprintf("rows=%d", len(v.Identities)))
	}
	var auth []byte
	var authSHA string
	e = tx.QueryRowContext(ctx, `SELECT decision_sha256,report FROM migration_auth_imports_0335 WHERE run_id=$1`, run).Scan(&authSHA, &auth)
	if missing(e) {
		add("authentication", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var a cr.Result
		if e = json.Unmarshal(auth, &a); e != nil {
			return v, e
		}
		state := "verified"
		if a.DryRun || !a.Complete || a.ManualReset > 0 || len(a.Rows) == 0 || a.IdentitySHA256 != idsHash {
			state = "blocked"
		}
		add("authentication", state, authSHA, fmt.Sprintf("imported=%d manual_reset=%d", a.Imported, a.ManualReset))
		for _, row := range a.Rows {
			status, reason := "manual", "existing Never credentials unchanged"
			if row.State == "imported" {
				status, reason = "transferred", ""
			}
			if row.State == "manual_reset" {
				reason = "unsupported password verifier; reset required"
			}
			v.Items = append(v.Items, rr.Item{Kind: "account", Source: row.Provider + "/" + row.SourceID, Target: row.UUID, Status: status, Reason: reason})
		}
	}
	var sec []byte
	var secHash string
	e = tx.QueryRowContext(ctx, `SELECT manifest_public_sha256,report FROM migration_security_resets_0336 WHERE run_id=$1`, run).Scan(&secHash, &sec)
	if missing(e) {
		add("security", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var s MigrationSecurityReport0336
		if e = json.Unmarshal(sec, &s); e != nil {
			return v, e
		}
		st := "verified"
		if !s.Verified || s.ManualResets > 0 || !s.RequiresLogin || !s.RequiresDeviceEnrollment || !s.RequiresGuardAttestation {
			st = "blocked"
		}
		add("security", st, secHash, "new Never trust chain; legacy sessions not migrated")
	}
	rows, qe := tx.QueryContext(ctx, `SELECT c.profile_path,c.files_sha256,c.report,w.data FROM migration_content_0337 c JOIN build_workspaces_0226 w ON w.id=c.workspace_id WHERE c.run_id=$1 ORDER BY c.profile_path`, run)
	if qe != nil {
		return v, qe
	}
	contents := 0
	for rows.Next() {
		var profile, hash string
		var raw, wsRaw []byte
		if qe = rows.Scan(&profile, &hash, &raw, &wsRaw); qe != nil {
			break
		}
		contents++
		var plan gc.Plan
		var ws BuildWorkspace
		if qe = json.Unmarshal(raw, &plan); qe != nil {
			break
		}
		if qe = json.Unmarshal(wsRaw, &ws); qe != nil {
			break
		}
		target := map[string]BuildFile{}
		for _, f := range ws.Files {
			target[f.Path] = f
		}
		ready := plan.Ready && plan.FilesSHA256 == hash && ws.State != "importing" && ws.State != "failed" && len(plan.Blockers) == 0 && len(plan.Files) > 0
		for _, f := range plan.Files {
			saved, exists := target[f.TargetPath]
			ok := exists && saved.SHA256 == f.SHA256 && saved.Size == f.Size
			st := "manual"
			reason := "not verified in Build Workspace"
			if ok {
				st = "transferred"
				reason = ""
			}
			if !ok {
				ready = false
			}
			coveredSources[f.SourcePath] = true
			v.Items = append(v.Items, rr.Item{Kind: "client_file", Source: f.SourcePath, Target: ws.ProfileID + "/" + f.TargetPath, Status: st, SHA256: f.SHA256, Reason: reason})
		}
		profileState := "transformed"
		reason := ""
		if !ready {
			profileState = "manual"
			reason = "workspace files incomplete or changed"
		}
		coveredSources[profile] = true
		v.Items = append(v.Items, rr.Item{Kind: "client_profile", Source: profile, Target: ws.ProfileID, Status: profileState, SHA256: hash, Reason: reason})
		st := "verified"
		if !ready {
			st = "blocked"
		}
		add("content_profile:"+profile, st, hash, fmt.Sprintf("workspace=%s files=%d", ws.ID, len(plan.Files)))
	}
	if qe == nil {
		qe = rows.Err()
	}
	rows.Close()
	if qe != nil {
		return v, qe
	}
	if contents == 0 {
		add("content", "missing", "", "")
	} else {
		st := "verified"
		for _, p := range v.Evidence {
			if strings.HasPrefix(p.Stage, "content_profile:") && p.State != "verified" {
				st = "blocked"
			}
		}
		add("content", st, "", fmt.Sprintf("profiles=%d", contents))
	}
	var moduleJSON []byte
	var modSource, modInventory string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,inventory_sha256,report FROM migration_modules_0338 WHERE run_id=$1`, run).Scan(&modSource, &modInventory, &moduleJSON)
	if missing(e) {
		add("modules", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var m gm.Report
		if e = json.Unmarshal(moduleJSON, &m); e != nil {
			return v, e
		}
		state := "verified"
		if !m.Ready || len(m.Blockers) > 0 || modSource != v.SourceSHA256 || modInventory != v.InventorySHA256 {
			state = "blocked"
		}
		add("modules", state, modInventory, fmt.Sprintf("modules=%d wrappers=%d", len(m.Modules), len(m.Wrappers)))
		for _, mod := range m.Modules {
			coveredSources[mod.Path] = true
			status := "manual"
			if mod.Status == "blocked" || mod.Implementation == "blocker" {
				status = "blocked"
			}
			v.Items = append(v.Items, rr.Item{Kind: "module", Source: mod.Path, Status: status, SHA256: mod.SHA256, Reason: mod.Reason})
		}
		for _, wrapper := range m.Wrappers {
			coveredSources[wrapper.Path] = true
			status := "manual"
			if wrapper.Status == "blocked" {
				status = "blocked"
			}
			v.Items = append(v.Items, rr.Item{Kind: "server_wrapper", Source: wrapper.Path, Status: status, SHA256: wrapper.SHA256, Reason: wrapper.Reason})
		}
	}
	add("player_assistant", "manual", "", "desktop adoption and signed installer must be independently tested on supported OS; no server receipt")
	var rehearsalJSON []byte
	var rehearsalHash string
	e = tx.QueryRowContext(ctx, `SELECT report_sha256,report FROM migration_rehearsals_03310 WHERE run_id=$1 ORDER BY recorded_at DESC,stage_id DESC LIMIT 1`, run).Scan(&rehearsalHash, &rehearsalJSON)
	if missing(e) {
		add("rehearsal", "missing", "", "")
	} else if e != nil {
		return v, e
	} else {
		var rehearse gr.Report
		if e = json.Unmarshal(rehearsalJSON, &rehearse); e != nil {
			return v, e
		}
		recomputed, er := gr.Evaluate(rehearse)
		if er != nil {
			return v, er
		}
		state := "verified"
		if !recomputed.Ready || !rehearse.Ready || rehearse.SourceInventorySHA256 != v.InventorySHA256 {
			state = "blocked"
		}
		add("rehearsal", state, rehearsalHash, "stage="+rehearse.StageID)
	}
	routes, qe := tx.QueryContext(ctx, `SELECT c.profile_id,c.channel,c.state,c.target_digest,c.fence_evidence_sha256,c.release_id,c.activated_revision,h.release_id,h.manifest_digest FROM migration_cutovers_03311 c LEFT JOIN channel_heads h ON h.project_id=c.project_id AND h.profile_id=c.profile_id AND h.channel=c.channel WHERE c.run_id=$1 ORDER BY c.profile_id,c.channel`, run)
	if qe != nil {
		return v, qe
	}
	routeCount := 0
	active := 0
	for routes.Next() {
		var profile, channel, state, sha, fence, release string
		var activated sql.NullInt64
		var headRelease, headDigest sql.NullString
		if qe = routes.Scan(&profile, &channel, &state, &sha, &fence, &release, &activated, &headRelease, &headDigest); qe != nil {
			break
		}
		routeCount++
		st := "verified"
		if state == "active" {
			active++
			if !activated.Valid || headRelease.String != release || headDigest.String != sha || fence == "" {
				st = "blocked"
			}
		} else if state == "staged" {
			st = "manual"
		} else if state == "cancelled" {
			st = "manual"
		} else if state == "rolled_back" {
			st = "verified"
		} else {
			st = "blocked"
		}
		add("cutover_scope:"+profile+"/"+channel, st, sha, state)
	}
	if qe == nil {
		qe = routes.Err()
	}
	routes.Close()
	if qe != nil {
		return v, qe
	}
	if routeCount == 0 {
		add("cutover", "missing", "", "")
	} else {
		st := "verified"
		if active == 0 {
			st = "manual"
		}
		add("cutover", st, "", fmt.Sprintf("routes=%d active=%d", routeCount, active))
	}
	rollbacks, qe := tx.QueryContext(ctx, `SELECT profile_id,channel,plan_sha256,state,result FROM migration_rollbacks_03312 WHERE run_id=$1 ORDER BY profile_id,channel`, run)
	if qe != nil {
		return v, qe
	}
	rollbackCount := 0
	for rollbacks.Next() {
		var profile, channel, hash, state string
		var raw []byte
		if qe = rollbacks.Scan(&profile, &channel, &hash, &state, &raw); qe != nil {
			break
		}
		rollbackCount++
		status := "verified"
		if state != "completed" {
			status = "blocked"
		}
		add("rollback_scope:"+profile+"/"+channel, status, hash, state)
	}
	if qe == nil {
		qe = rollbacks.Err()
	}
	rollbacks.Close()
	if qe != nil {
		return v, qe
	}
	if rollbackCount == 0 {
		add("rollback", "missing", "", "no rollback rehearsal receipt; real cutover rollback not assumed")
	} else {
		add("rollback", "verified", "", fmt.Sprintf("receipts=%d", rollbackCount))
	}
	events, qe := tx.QueryContext(ctx, `SELECT seq,kind,revision FROM migration_events_0331 WHERE run_id=$1 AND kind<>'gravit_report_rc_reviewed' ORDER BY seq LIMIT 10001`, run)
	if qe != nil {
		return v, qe
	}
	for events.Next() {
		var d rr.Decision
		if qe = events.Scan(&d.Sequence, &d.Kind, &d.Revision); qe != nil {
			break
		}
		v.Decisions = append(v.Decisions, d)
	}
	if qe == nil {
		qe = events.Err()
	}
	events.Close()
	if qe != nil {
		return v, qe
	}
	// RC review is an audit side-effect, not a migration input change.
	// Exclude that self-referential event and its run revision from the hash.
	if len(v.Decisions) > 0 {
		v.RunRevision = v.Decisions[len(v.Decisions)-1].Revision
	}
	if len(v.Decisions) > 10000 {
		v.Blockers = append(v.Blockers, "audit event limit exceeded; export and verify complete history")
	}
	// The replacement entries carry the actual target mapping and status.
	filtered := make([]rr.Item, 0, len(v.Items))
	for i, item := range v.Items {
		if i < inventoryItemCount && coveredSources[item.Source] {
			continue
		}
		filtered = append(filtered, item)
	}
	v.Items = filtered
	return rr.Finalize(v)
}

func (r *SQLRepository) BuildMigrationReport03313(ctx context.Context, run string) (rr.Report, error) {
	if e := r.check(); e != nil {
		return rr.Report{}, e
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return rr.Report{}, e
	}
	defer tx.Rollback()
	v, e := migrationEvidence03313(ctx, tx, run)
	if e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return rr.Report{}, e
	}
	return v, nil
}

type MigrationReview03313 struct {
	Report            rr.Report `json:"report"`
	ReviewedBy        string    `json:"reviewedBy"`
	EvidenceSHA256    string    `json:"evidenceSha256"`
	EvidenceReference string    `json:"evidenceReference"`
	ReviewedAt        string    `json:"reviewedAt"`
	Status            string    `json:"status"`
}

// Review seals the exact read snapshot and does not pronounce a deployment
// certified. Digest races are detected under the run lock before the commit.
func (r *SQLRepository) ReviewMigrationReport03313(ctx context.Context, run, expected, actor, reference, evidence string) (MigrationReview03313, error) {
	if e := r.check(); e != nil {
		return MigrationReview03313{}, e
	}
	if len(actor) < 1 || len(actor) > 128 || len(reference) < 8 || len(reference) > 256 || strings.ContainsAny(reference, "\x00\n\r") || len(evidence) != 64 {
		return MigrationReview03313{}, mw.ErrConflict
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if e != nil {
		return MigrationReview03313{}, e
	}
	defer tx.Rollback()
	var locked string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, run).Scan(&locked); e != nil {
		return MigrationReview03313{}, e
	}
	// Check the immutable receipt FIRST. The review event changes the run
	// revision, so a replay cannot compare against a freshly changed snapshot.
	var priorDigest, priorActor, priorEvidence, priorRef, priorAt string
	var priorRaw []byte
	e = tx.QueryRowContext(ctx, `SELECT report_sha256,reviewed_by,evidence_sha256,evidence_reference,reviewed_at::text,report FROM migration_reports_03313 WHERE run_id=$1`, run).Scan(&priorDigest, &priorActor, &priorEvidence, &priorRef, &priorAt, &priorRaw)
	if e == nil {
		if priorDigest != expected || priorActor != actor || priorEvidence != evidence || priorRef != reference {
			return MigrationReview03313{}, mw.ErrConflict
		}
		var prior rr.Report
		if er := json.Unmarshal(priorRaw, &prior); er != nil {
			return MigrationReview03313{}, er
		}
		if er := rr.Verify(prior); er != nil {
			return MigrationReview03313{}, er
		}
		if e = tx.Commit(); e != nil {
			return MigrationReview03313{}, e
		}
		return MigrationReview03313{Report: prior, ReviewedBy: actor, EvidenceSHA256: evidence, EvidenceReference: reference, ReviewedAt: priorAt, Status: "rc_reviewed_not_ga_certified"}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return MigrationReview03313{}, e
	}
	report, e := migrationEvidence03313(ctx, tx, run)
	if e != nil {
		return MigrationReview03313{}, e
	}
	if report.ReportSHA256 != expected || report.Status != "review_required" || len(report.Blockers) > 0 {
		return MigrationReview03313{}, mw.ErrConflict
	}
	for _, b := range evidence {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return MigrationReview03313{}, mw.ErrConflict
		}
	}
	data, e := json.Marshal(report)
	if e != nil {
		return MigrationReview03313{}, e
	}
	var reviewedAt string
	e = tx.QueryRowContext(ctx, `INSERT INTO migration_reports_03313(run_id,report_sha256,report,reviewed_by,evidence_sha256,evidence_reference) VALUES($1,$2,$3::jsonb,$4,$5,$6) RETURNING reviewed_at::text`, run, expected, string(data), actor, evidence, reference).Scan(&reviewedAt)
	if e != nil {
		return MigrationReview03313{}, e
	}
	// Audit records a hash and the reviewer's decision, never the raw evidence.
	var revision int64
	if e = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, run).Scan(&revision); e != nil {
		return MigrationReview03313{}, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_report_rc_reviewed','source_assessment',$2,jsonb_build_object('reportSha256',$3::text,'evidenceSha256',$4::text))`, run, revision, expected, evidence)
	if e != nil {
		return MigrationReview03313{}, e
	}
	if e = tx.Commit(); e != nil {
		return MigrationReview03313{}, fmt.Errorf("RC report commit uncertain; query reviewed report before retry: %w", e)
	}
	return MigrationReview03313{Report: report, ReviewedBy: actor, EvidenceSHA256: evidence, EvidenceReference: reference, ReviewedAt: reviewedAt, Status: "rc_reviewed_not_ga_certified"}, nil
}
func (r *SQLRepository) GetReviewedMigrationReport03313(ctx context.Context, run string) (MigrationReview03313, error) {
	if e := r.check(); e != nil {
		return MigrationReview03313{}, e
	}
	var out MigrationReview03313
	var raw []byte
	e := r.db.QueryRowContext(ctx, `SELECT report,reviewed_by,evidence_sha256,evidence_reference,reviewed_at::text FROM migration_reports_03313 WHERE run_id=$1`, run).Scan(&raw, &out.ReviewedBy, &out.EvidenceSHA256, &out.EvidenceReference, &out.ReviewedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return out, mw.ErrNotFound
	}
	if e != nil {
		return out, e
	}
	if e = json.Unmarshal(raw, &out.Report); e != nil {
		return out, e
	}
	if e = rr.Verify(out.Report); e != nil {
		return out, e
	}
	out.Status = "rc_reviewed_not_ga_certified"
	return out, nil
}
