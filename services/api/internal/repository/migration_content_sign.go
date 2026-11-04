package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// VerifyMigrationContentBeforeSign0337 is a last-mile guard: a migrated build
// can only be signed if it contains the exact source-vetted bytes and a
// completed optional catalog. Other (non-migration) releases are unaffected.
func (r *SQLRepository) VerifyMigrationContentBeforeSign0337(ctx context.Context, projectID, packageID string, manifest model.Manifest) error {
	if e := r.check(); e != nil {
		return e
	}
	rows, e := r.db.QueryContext(ctx, `SELECT c.run_id,c.report FROM migration_content_0337 c JOIN build_workspaces_0226 w ON w.id=c.workspace_id WHERE (w.data->>'packageId')=$1 AND w.project_id=$2`, packageID, projectID)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			return errors.New("multiple migration owners for release")
		}
		var raw []byte
		var runID string
		if e = rows.Scan(&runID, &raw); e != nil {
			return e
		}
		var plan gc.Plan
		if e = json.Unmarshal(raw, &plan); e != nil {
			return e
		}
		if e = checkMigrationContentSign0337(plan, manifest); e != nil {
			return e
		}
		var moduleRaw []byte
		if e = r.db.QueryRowContext(ctx, `SELECT report FROM migration_modules_0338 WHERE run_id=$1`, runID).Scan(&moduleRaw); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return errors.New("MIG08 module review required before signing migrated release")
			}
			return e
		}
		var moduleReport gm.Report
		if e = json.Unmarshal(moduleRaw, &moduleReport); e != nil {
			return e
		}
		if e = verifyModuleRelease0338(plan, moduleReport); e != nil {
			return e
		}
	}
	return rows.Err()
}
func checkMigrationContentSign0337(p gc.Plan, m model.Manifest) error {
	if !p.Ready || p.Profile.Profile.ID != m.ProfileID {
		return errors.New("migration profile not verified")
	}
	expected := map[string]gc.File{}
	for _, f := range p.Files {
		expected[f.TargetPath] = f
	}
	if len(expected) != len(p.Files) || len(m.Files) != len(expected) {
		return errors.New("migration content file count mismatch")
	}
	for _, f := range m.Files {
		actual, ok := expected[f.Path]
		if !ok || f.Size != actual.Size || f.SHA256 != actual.SHA256 || model.FileOwnership0224(f) != actual.Ownership {
			return fmt.Errorf("migration content changed before signing: %s", f.Path)
		}
	}
	if p.Optional != nil {
		if !p.Optional.Ready || m.SchemaVersion != model.ManifestSchemaV3 || m.ComponentCatalog == nil || !reflect.DeepEqual(m.ComponentCatalog.Components, p.Optional.Catalog.Components) || !reflect.DeepEqual(m.ComponentCatalog.Categories, p.Optional.Catalog.Categories) || !reflect.DeepEqual(m.ComponentCatalog.Groups, p.Optional.Catalog.Groups) || !reflect.DeepEqual(m.ComponentCatalog.Presets, p.Optional.Catalog.Presets) {
			return errors.New("Gravit optional catalog has not been applied and verified")
		}
	}
	return nil
}

// A signed content release cannot assert a safe launch migration while the
// pinned module assessment is missing or contains unreviewed executable JARs.
func verifyModuleRelease0338(plan gc.Plan, report gm.Report) error {
	if report.Format != gm.Format || report.SourceSHA256 != plan.SourceSHA256 || report.InventorySHA256 != plan.InventorySHA256 ||
		!report.Ready || len(report.Blockers) > 0 || report.CutoverAllowed {
		return errors.New("MIG08 module review blocks migrated release signing")
	}
	return nil
}
