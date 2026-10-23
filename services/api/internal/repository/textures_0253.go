package repository

import (
	"context"
	"errors"
	"fmt"
)

// TextureGarbage0253 is leased to one GC worker for up to 15 minutes.
// Only unreferenced blobs past the backup grace window can be leased.
type TextureGarbage0253 struct {
	Digest    string
	Driver    string
	ObjectKey string
}

// ClaimTextureGarbage0253 isolates candidates from public reads before deletion.
// A 7-day grace period preserves recent replacement history and allows backups.
func (r *SQLRepository) ClaimTextureGarbage0253(ctx context.Context, driver string, limit int) ([]TextureGarbage0253, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if driver != "local" && driver != "s3" {
		return nil, errors.New("invalid texture driver")
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("texture GC batch must be between 1 and 100")
	}
	rows, err := r.db.QueryContext(ctx, `WITH candidates AS (
   SELECT b.digest FROM texture_blobs b WHERE b.storage_driver=$1
     AND b.created_at < now()-interval '7 days'
     AND b.last_upload_at < now()-interval '7 days'
     AND (b.status IN ('verified','staging') OR (b.status='quarantined'
       AND (b.gc_claimed_at IS NULL OR b.gc_claimed_at < now()-interval '15 minutes')))
     AND NOT EXISTS (SELECT 1 FROM texture_assignments a WHERE a.blob_digest=b.digest)
     AND NOT EXISTS (SELECT 1 FROM texture_saved_items i WHERE i.digest=b.digest)
     AND NOT EXISTS (SELECT 1 FROM texture_project_policies p
       WHERE p.default_skin_digest=b.digest OR p.default_cape_digest=b.digest)
     AND NOT EXISTS (SELECT 1 FROM texture_assignment_revisions rev
       WHERE rev.created_at >= now()-interval '7 days'
       AND rev.snapshot->>'blobDigest'=b.digest)
   ORDER BY b.created_at,b.digest FOR UPDATE OF b SKIP LOCKED LIMIT $2
 ) UPDATE texture_blobs b SET status='quarantined',verified_at=NULL,gc_claimed_at=now()
   FROM candidates c WHERE b.digest=c.digest RETURNING b.digest,b.storage_driver,b.object_key`, driver, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureGarbage0253, 0)
	for rows.Next() {
		var item TextureGarbage0253
		if err := rows.Scan(&item.Digest, &item.Driver, &item.ObjectKey); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// FinishTextureGarbage0253 removes the DB record and associated quota entries.
// It will never delete an object that became referenced after its GC lease.
func (r *SQLRepository) FinishTextureGarbage0253(ctx context.Context, digest string) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM texture_blobs b WHERE b.digest=$1 AND b.status='quarantined'
  AND NOT EXISTS (SELECT 1 FROM texture_assignments a WHERE a.blob_digest=b.digest)
  AND NOT EXISTS (SELECT 1 FROM texture_saved_items i WHERE i.digest=b.digest)
  AND NOT EXISTS (SELECT 1 FROM texture_project_policies p
    WHERE p.default_skin_digest=b.digest OR p.default_cape_digest=b.digest)`, digest)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("texture GC lease no longer valid for %s", digest)
	}
	return nil
}

// TextureBackupRow0253 is a consistent ordered metadata view for snapshots.
type TextureBackupRow0253 struct {
	Digest            string
	ByteSize          int64
	Driver, ObjectKey string
}

func (r *SQLRepository) TextureBackupRows0253(ctx context.Context, driver string) ([]TextureBackupRow0253, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if driver != "local" && driver != "s3" {
		return nil, errors.New("invalid driver")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT digest,byte_size,storage_driver,object_key FROM texture_blobs
  WHERE status='verified' AND storage_driver=$1 ORDER BY digest`, driver)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureBackupRow0253, 0)
	for rows.Next() {
		var b TextureBackupRow0253
		if err := rows.Scan(&b.Digest, &b.ByteSize, &b.Driver, &b.ObjectKey); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (r *SQLRepository) ReleaseTextureGarbage0253(ctx context.Context, digest string) error {
	if err := r.check(); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE texture_blobs SET gc_claimed_at=now()-interval '16 minutes' WHERE digest=$1 AND status='quarantined'`, digest)
	return err
}
