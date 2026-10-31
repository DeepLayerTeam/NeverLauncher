package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

func migrationIdentityTargets0334(ctx context.Context, tx *sql.Tx) ([]gi.Target, error) {
	// Inspect both Never's local/remote Minecraft identity and verified official
	// identities; contradictory claims are deliberately not silently de-duped.
	rows, e := tx.QueryContext(ctx, `SELECT uuid,name,user_id,'minecraft_profiles' FROM minecraft_profiles UNION ALL
 SELECT minecraft_uuid,minecraft_name,never_user_id,'official_link' FROM official_never_identity_links_0268`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []gi.Target{}
	for rows.Next() {
		var t gi.Target
		if e = rows.Scan(&t.UUID, &t.Username, &t.UserID, &t.Source); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func identityReport0334(runID, source, manifest, digest string, rows []gi.Mapping, sum map[string]int) gi.Report {
	return gi.Report{Format: gi.Format, RunID: runID, SourceSHA256: source, InventorySHA256: manifest, EntriesSHA256: digest, Rows: rows, Summary: sum, Ready: sum["blocked"] == 0 && sum["pending_import"] == 0 && sum["matched"] > 0}
}
func migrationIdentityRows0334(ctx context.Context, tx *sql.Tx, id string) ([]gi.Account, error) {
	rows, e := tx.QueryContext(ctx, `SELECT provider,source_id,username,minecraft_uuid,source_path FROM migration_identity_rows_0334 WHERE run_id=$1 ORDER BY ordinal`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []gi.Account{}
	for rows.Next() {
		var a gi.Account
		if e = rows.Scan(&a.Provider, &a.SourceID, &a.Username, &a.UUID, &a.SourcePath); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func previousIdentitySignature0334(ctx context.Context, tx *sql.Tx, id string) string {
	var signature string
	_ = tx.QueryRowContext(ctx, `SELECT detail->>'mappingSha256' FROM migration_events_0331 WHERE run_id=$1 AND kind='gravit_identity_mapped' ORDER BY seq DESC LIMIT 1`, id).Scan(&signature)
	return signature
}
func saveIdentityRows0334(ctx context.Context, tx *sql.Tx, id string, rows []gi.Mapping) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM migration_identity_rows_0334 WHERE run_id=$1`, id); e != nil {
		return e
	}
	// Batch inserts keep network and PostgreSQL statement overhead bounded even
	// for large FileAuth/SQL snapshots (<=200000 players).
	for start := 0; start < len(rows); start += 250 {
		end := start + 250
		if end > len(rows) {
			end = len(rows)
		}
		var q strings.Builder
		q.WriteString(`INSERT INTO migration_identity_rows_0334(run_id,ordinal,provider,source_id,username,minecraft_uuid,source_path,target_user_id,status,reason) VALUES `)
		args := make([]any, 0, (end-start)*10)
		for i := start; i < end; i++ {
			if i > start {
				q.WriteByte(',')
			}
			q.WriteByte('(')
			for j := 0; j < 10; j++ {
				if j != 0 {
					q.WriteByte(',')
				}
				fmt.Fprintf(&q, "$%d", len(args)+j+1)
			}
			q.WriteByte(')')
			m := rows[i]
			var target any
			if m.TargetUserID != "" {
				target = m.TargetUserID
			}
			args = append(args, id, i, m.Provider, m.SourceID, m.Username, m.UUID, m.SourcePath, target, m.Status, m.Reason)
		}
		if _, e := tx.ExecContext(ctx, q.String(), args...); e != nil {
			return e
		}
	}
	return nil
}
func (r *SQLRepository) SaveMigrationIdentities0334(ctx context.Context, id string, source, manifest string, accounts []gi.Account) (gi.Report, error) {
	if e := r.check(); e != nil {
		return gi.Report{}, e
	}
	if len(accounts) == 0 || len(accounts) > gi.MaxAccounts {
		return gi.Report{}, errors.New("empty or oversized identity snapshot")
	}
	digest, e := gi.Digest(accounts)
	if e != nil {
		return gi.Report{}, e
	}
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return gi.Report{}, e
	}
	defer tx.Rollback()
	var status, step, kind string
	e = tx.QueryRowContext(ctx, `SELECT status,step,source_kind FROM migration_runs_0331 WHERE id=$1 FOR UPDATE`, id).Scan(&status, &step, &kind)
	if errors.Is(e, sql.ErrNoRows) {
		return gi.Report{}, mw.ErrNotFound
	}
	if e != nil {
		return gi.Report{}, e
	}
	if status != "prepared" || step != "source_assessment" || kind != "gravit" {
		return gi.Report{}, mw.ErrBusy
	}
	var invSource, invManifest string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,manifest_sha256 FROM migration_source_inventory_0333 WHERE run_id=$1`, id).Scan(&invSource, &invManifest)
	if errors.Is(e, sql.ErrNoRows) {
		return gi.Report{}, errors.New("source inventory must be saved before identity mapping")
	}
	if e != nil {
		return gi.Report{}, e
	}
	if source != invSource || manifest != invManifest {
		return gi.Report{}, mw.ErrConflict
	}
	var prevDigest string
	e = tx.QueryRowContext(ctx, `SELECT entries_sha256 FROM migration_identity_snapshots_0334 WHERE run_id=$1`, id).Scan(&prevDigest)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return gi.Report{}, e
	}
	if e == nil && prevDigest != digest {
		return gi.Report{}, mw.ErrConflict
	} // never silently overwrite an approved source map
	targets, e := migrationIdentityTargets0334(ctx, tx)
	if e != nil {
		return gi.Report{}, e
	}
	mapped, sum := gi.Reconcile(accounts, targets)
	if prevDigest == "" {
		_, e = tx.ExecContext(ctx, `INSERT INTO migration_identity_snapshots_0334(run_id,source_sha256,inventory_sha256,entries_sha256) VALUES($1,$2,$3,$4)`, id, source, manifest, digest)
		if e != nil {
			return gi.Report{}, e
		}
	}
	if prevDigest != "" && previousIdentitySignature0334(ctx, tx, id) == digestMappings0334(mapped) {
		if _, e = tx.ExecContext(ctx, `UPDATE migration_identity_snapshots_0334 SET verified_at=now() WHERE run_id=$1`, id); e != nil {
			return gi.Report{}, e
		}
		if e = tx.Commit(); e != nil {
			return gi.Report{}, e
		}
		return identityReport0334(id, source, manifest, digest, mapped, sum), nil
	}
	if e = saveIdentityRows0334(ctx, tx, id, mapped); e != nil {
		return gi.Report{}, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE migration_identity_snapshots_0334 SET verified_at=now() WHERE run_id=$1`, id); e != nil {
		return gi.Report{}, e
	}
	// Same source and unchanged target must not manufacture replay revisions.
	var previousSignature string
	if prevDigest != "" { // always reverify targets; journal is only appended on first snapshot or changed resolution
		// Last recorded signature comes from independently stored event detail.
		_ = tx.QueryRowContext(ctx, `SELECT detail->>'mappingSha256' FROM migration_events_0331 WHERE run_id=$1 AND kind='gravit_identity_mapped' ORDER BY seq DESC LIMIT 1`, id).Scan(&previousSignature)
	}
	signature := digestMappings0334(mapped)
	if prevDigest == "" || previousSignature != signature {
		var revision int64
		if e = tx.QueryRowContext(ctx, `UPDATE migration_runs_0331 SET revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, id).Scan(&revision); e != nil {
			return gi.Report{}, e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO migration_events_0331(run_id,kind,step,revision,detail) VALUES($1,'gravit_identity_mapped','source_assessment',$2,jsonb_build_object('accounts',$3::int,'matched',$4::int,'pendingImport',$5::int,'blocked',$6::int,'mappingSha256',$7::text))`, id, revision, len(mapped), sum["matched"], sum["pending_import"], sum["blocked"], signature)
		if e != nil {
			return gi.Report{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return gi.Report{}, fmt.Errorf("identity commit uncertain; retry same source: %w", e)
	}
	return identityReport0334(id, source, manifest, digest, mapped, sum), nil
}
func digestMappings0334(rows []gi.Mapping) string {
	h := sha256.New()
	for _, m := range rows {
		for _, part := range []string{m.Provider, m.SourceID, m.Username, m.UUID, m.TargetUserID, m.Status, m.Reason} {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (r *SQLRepository) GetMigrationIdentities0334(ctx context.Context, id string) (gi.Report, error) {
	if e := r.check(); e != nil {
		return gi.Report{}, e
	}
	// Read snapshot and its mapping rows in one consistent PostgreSQL snapshot.
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return gi.Report{}, e
	}
	defer tx.Rollback()
	var source, manifest, digest string
	e = tx.QueryRowContext(ctx, `SELECT source_sha256,inventory_sha256,entries_sha256 FROM migration_identity_snapshots_0334 WHERE run_id=$1`, id).Scan(&source, &manifest, &digest)
	if errors.Is(e, sql.ErrNoRows) {
		return gi.Report{}, mw.ErrNotFound
	}
	if e != nil {
		return gi.Report{}, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT provider,source_id,username,minecraft_uuid,source_path,COALESCE(target_user_id,''),status,reason FROM migration_identity_rows_0334 WHERE run_id=$1 ORDER BY ordinal`, id)
	if e != nil {
		return gi.Report{}, e
	}
	out := []gi.Mapping{}
	sum := map[string]int{"matched": 0, "pending_import": 0, "blocked": 0}
	for rows.Next() {
		var m gi.Mapping
		if e = rows.Scan(&m.Provider, &m.SourceID, &m.Username, &m.UUID, &m.SourcePath, &m.TargetUserID, &m.Status, &m.Reason); e != nil {
			rows.Close()
			return gi.Report{}, e
		}
		out = append(out, m)
		sum[m.Status]++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return gi.Report{}, e
	}
	if e = tx.Commit(); e != nil {
		return gi.Report{}, e
	}
	return identityReport0334(id, source, manifest, digest, out, sum), nil
}
func (r *SQLRepository) VerifyMigrationIdentities0334(ctx context.Context, id string) (gi.Report, error) {
	if e := r.check(); e != nil {
		return gi.Report{}, e
	}
	// Load a stable snapshot, then delegate to Save which serializes the run
	// and rechecks the source checksum and current target ownership atomically.
	report, e := r.GetMigrationIdentities0334(ctx, id)
	if e != nil {
		return gi.Report{}, e
	}
	accounts := make([]gi.Account, 0, len(report.Rows))
	for _, m := range report.Rows {
		accounts = append(accounts, m.Account)
	}
	return r.SaveMigrationIdentities0334(ctx, id, report.SourceSHA256, report.InventorySHA256, accounts)
}
