package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DeleteTextureWithLease02512 keeps the PostgreSQL blob row locked throughout
// the physical delete. All assignments, saved items, defaults and backup pins
// refer to this row through foreign keys, so a concurrent reference cannot be
// committed between the final eligibility check and removal from storage.
// This avoids the check/delete/finish race of the legacy maintenance command.
func (r *SQLRepository) DeleteTextureWithLease02512(ctx context.Context, candidate TextureGCLease02511, remove func(context.Context, string) error) error {
	if err := r.check(); err != nil {
		return err
	}
	if err := textureStorageDriver02511(candidate.Driver); err != nil {
		return err
	}
	if !validTextureDigest0255(candidate.Digest) || len(candidate.Token) != 64 || remove == nil ||
		candidate.ObjectKey != "texture-blobs/sha256/"+candidate.Digest[:2]+"/"+candidate.Digest+".png" {
		return errors.New("invalid fenced texture GC request")
	}
	for _, c := range candidate.Token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("invalid GC lease token")
		}
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock the blob row before checking references. Foreign-key writers acquiring
	// KEY SHARE on this row cannot proceed until commit; existing references are
	// seen by the following SELECT under READ COMMITTED.
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT digest FROM texture_blobs
  WHERE digest=$1 AND storage_driver=$2 AND object_key=$3
    AND status='quarantined' AND gc_lease_token=$4
    AND gc_claimed_at > now()-interval '45 minutes'
  FOR UPDATE`, candidate.Digest, candidate.Driver, candidate.ObjectKey, candidate.Token).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("stale texture GC lease: %s", candidate.Digest)
	}
	if err != nil {
		return err
	}
	var inUse bool
	err = tx.QueryRowContext(ctx, `SELECT
  EXISTS(SELECT 1 FROM texture_assignments WHERE blob_digest=$1)
  OR EXISTS(SELECT 1 FROM texture_saved_items WHERE digest=$1)
  OR EXISTS(SELECT 1 FROM texture_project_policies WHERE default_skin_digest=$1 OR default_cape_digest=$1 OR fallback_skin_digest=$1 OR fallback_cape_digest=$1)
  OR EXISTS(SELECT 1 FROM texture_backup_pins WHERE digest=$1 AND expires_at>now())
  OR EXISTS(SELECT 1 FROM texture_assignment_revisions WHERE created_at >= now()-interval '7 days' AND snapshot->>'blobDigest'=$1)`, digest).Scan(&inUse)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("texture acquired a reference during GC: %s", digest)
	}
	// The callback operates on immutable content and must fail closed if the
	// digest, ETag or storage object has changed. No destructive DB operation is
	// committed when the physical delete fails.
	if err := remove(ctx, digest); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM texture_blobs
  WHERE digest=$1 AND status='quarantined' AND gc_lease_token=$2`, digest, candidate.Token)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("fenced GC delete affected an unexpected number of rows")
	}
	return tx.Commit()
}
