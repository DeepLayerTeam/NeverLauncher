package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var ErrTextureNotSelected0255 = errors.New("no selected texture")
var ErrTextureInUse0255 = errors.New("texture is still selected")

// TextureSavedItem0255 is a verified, per-account PNG, not an arbitrary URL.
type TextureSavedItem0255 struct {
	Digest         string     `json:"digest"`
	Kind           string     `json:"kind"`
	Model          string     `json:"model"`
	Source         string     `json:"source"`
	ByteSize       int64      `json:"bytes"`
	Width          int        `json:"width"`
	Height         int        `json:"height"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastSelectedAt *time.Time `json:"lastSelectedAt,omitempty"`
}

type TextureServiceRepository0255 interface {
	ListSavedTextures0255(context.Context, model.MinecraftProfile, string) ([]TextureSavedItem0255, error)
	SelectSavedTexture0255(context.Context, model.MinecraftProfile, string, string, int64, string, string) (model.TextureAssignment0251, error)
	ClearTexture0255(context.Context, model.MinecraftProfile, string, int64, bool) (model.TextureAssignment0251, error)
	DeleteSavedTexture0255(context.Context, model.MinecraftProfile, string, string) error
	ReadSavedTextureBlob0255(context.Context, model.MinecraftProfile, string, string) (TextureBlob0252, bool, error)
}

func validTextureDigest0255(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func validTextureKind0255(v string) bool { return v == "skin" || v == "cape" }
func localTextureOwner0255(p model.MinecraftProfile) bool {
	return p.Realm == "local" && p.Issuer == "neverlauncher" && p.UserID != "" && p.UUID != ""
}

// Serializes create-only, overwrite, reset and delete with UploadTexture0252.
// Also verifies ownership against the real Minecraft profile, never the JSON UUID.
func lockOwnedTexture0255(ctx context.Context, tx *sql.Tx, p model.MinecraftProfile) error {
	if !localTextureOwner0255(p) {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(252,hashtext($1))`, p.UUID); err != nil {
		return err
	}
	var found bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2)`, p.UUID, p.UserID).Scan(&found); err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

func texturePermission0255(ctx context.Context, tx *sql.Tx, p model.MinecraftProfile, kind string) error {
	var allowed bool
	err := tx.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('', $1, $2)`, p.UserID, kind).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		if kind == "cape" {
			return ErrTextureCapeDenied0251
		}
		return ErrTextureUploadDenied0252
	}
	return nil
}

func (r *SQLRepository) ListSavedTextures0255(ctx context.Context, p model.MinecraftProfile, kind string) ([]TextureSavedItem0255, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if !localTextureOwner0255(p) || (kind != "" && !validTextureKind0255(kind)) {
		return nil, ErrNotFound
	}
	rows, err := r.db.QueryContext(ctx, `SELECT i.digest,i.kind,i.model,i.source,b.byte_size,b.width,b.height,i.created_at,i.last_selected_at
 FROM texture_saved_items i JOIN texture_blobs b ON b.digest=i.digest
 JOIN minecraft_profiles p ON p.user_id=i.user_id
 WHERE p.uuid=$1 AND p.user_id=$2 AND ($3='' OR i.kind=$3) AND b.status='verified'
 ORDER BY i.created_at DESC,i.digest,i.kind LIMIT 500`, p.UUID, p.UserID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TextureSavedItem0255, 0)
	for rows.Next() {
		var v TextureSavedItem0255
		var ts sql.NullTime
		if err := rows.Scan(&v.Digest, &v.Kind, &v.Model, &v.Source, &v.ByteSize, &v.Width, &v.Height, &v.CreatedAt, &ts); err != nil {
			return nil, err
		}
		if ts.Valid {
			v.LastSelectedAt = &ts.Time
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func recordTextureRevision0255(ctx context.Context, tx *sql.Tx, a model.TextureAssignment0251, actor, event, reason string) error {
	snap, err := json.Marshal(map[string]any{"blobDigest": a.BlobDigest, "externalUrl": a.ExternalURL, "kind": a.Kind, "model": a.Model, "visibility": a.Visibility, "active": a.Active, "source": a.Source, "projectId": a.ProjectID})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO texture_assignment_revisions(assignment_id,revision,snapshot,actor_user_id,reason,event) VALUES($1,$2,$3,$4,$5,$6)`, a.ID, a.Revision, snap, actor, reason, event)
	return err
}

func (r *SQLRepository) SelectSavedTexture0255(ctx context.Context, p model.MinecraftProfile, kind, digest string, expected int64, skinModel, visibility string) (model.TextureAssignment0251, error) {
	var zero model.TextureAssignment0251
	if err := r.check(); err != nil {
		return zero, err
	}
	if !validTextureDigest0255(digest) || !validTextureKind0255(kind) || expected < 0 {
		return zero, fmt.Errorf("invalid texture selection")
	}
	if err := validateTextureSelection0251(kind, skinModel, visibility); err != nil {
		return zero, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err = lockOwnedTexture0255(ctx, tx, p); err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(253,hashtext($1))`, p.UserID); err != nil {
		return zero, err
	}
	if err = texturePermission0255(ctx, tx, p, kind); err != nil {
		return zero, err
	}
	// The join verifies that the actual account has saved this kind of normalized
	// PNG and still owns a verified object. The FOR SHARE lock excludes GC claims.
	var savedModel, savedSource string
	err = tx.QueryRowContext(ctx, `SELECT i.model,i.source FROM texture_saved_items i JOIN texture_blob_owners o
 ON o.user_id=i.user_id AND o.digest=i.digest JOIN texture_blobs b ON b.digest=i.digest
 WHERE i.user_id=$1 AND i.digest=$2 AND i.kind=$3 AND b.status='verified' FOR SHARE OF b`, p.UserID, digest, kind).Scan(&savedModel, &savedSource)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	if kind == "cape" && savedModel != "classic" {
		return zero, ErrNotFound
	}
	a, err := scanTextureAssignment0251(tx.QueryRowContext(ctx, textureAssignmentSelect0251+` WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind=$3 FOR UPDATE`, p.UUID, p.UserID, kind))
	now := time.Now().UTC()
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 {
			return zero, ErrTextureRevisionConflict0251
		}
		// Identity upsert is safe because it selects an owner-proven profile row.
		_, err = tx.ExecContext(ctx, `INSERT INTO texture_identities(realm,profile_uuid,user_id,profile_name,origin,local_profile_uuid)
 SELECT 'local-project',uuid,user_id,name,'local-profile',uuid FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2
 ON CONFLICT(realm,profile_uuid) DO UPDATE SET profile_name=EXCLUDED.profile_name WHERE texture_identities.user_id=EXCLUDED.user_id`, p.UUID, p.UserID)
		if err != nil {
			return zero, err
		}
		a, err = scanTextureAssignment0251(tx.QueryRowContext(ctx, `INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,blob_digest,source,model,visibility,revision,active,updated_at)
   VALUES('local-project',$1,$2,$3,$4,$8,$5,$6,1,true,$7)
   RETURNING id,realm,profile_uuid,user_id,project_id,launcher_profile_id,kind,COALESCE(blob_digest,''),external_url,source,model,visibility,revision,active,updated_at`, p.UUID, p.UserID, kind, digest, skinModel, visibility, now, savedSource))
		if err != nil {
			return zero, err
		}
	} else {
		if err != nil {
			return zero, err
		}
		if a.Revision != expected {
			return zero, ErrTextureRevisionConflict0251
		}
		a.Revision++
		a.BlobDigest = digest
		a.ExternalURL = ""
		a.Source = savedSource
		a.Model = skinModel
		a.Visibility = visibility
		a.Active = true
		a.UpdatedAt = now
		_, err = tx.ExecContext(ctx, `UPDATE texture_assignments SET blob_digest=$2,external_url='',source=$3,model=$4,visibility=$5,active=true,revision=$6,updated_at=$7 WHERE id=$1`, a.ID, a.BlobDigest, a.Source, a.Model, a.Visibility, a.Revision, now)
		if err != nil {
			return zero, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE texture_saved_items SET last_selected_at=$4,model=$5 WHERE user_id=$1 AND digest=$2 AND kind=$3`, p.UserID, digest, kind, now, skinModel); err != nil {
		return zero, err
	}
	if err = recordTextureRevision0255(ctx, tx, a, p.UserID, "select", "selected saved normalized PNG"); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return a, nil
}

// ClearTexture0255 retains the assignment and CAS counter but clears the
// reference. Delete also removes the asset from the player's saved library;
// other users' blobs and immutable revision history are never deleted.
func (r *SQLRepository) ClearTexture0255(ctx context.Context, p model.MinecraftProfile, kind string, expected int64, deleteAsset bool) (model.TextureAssignment0251, error) {
	var zero model.TextureAssignment0251
	if err := r.check(); err != nil {
		return zero, err
	}
	if !validTextureKind0255(kind) || expected < 1 {
		return zero, ErrTextureRevisionConflict0251
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err = lockOwnedTexture0255(ctx, tx, p); err != nil {
		return zero, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(253,hashtext($1))`, p.UserID); err != nil {
		return zero, err
	}
	a, err := scanTextureAssignment0251(tx.QueryRowContext(ctx, textureAssignmentSelect0251+` WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind=$3 FOR UPDATE`, p.UUID, p.UserID, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	if a.Revision != expected {
		return zero, ErrTextureRevisionConflict0251
	}
	oldDigest := a.BlobDigest
	a.BlobDigest = ""
	a.ExternalURL = ""
	a.Active = false
	a.Visibility = "private"
	a.Revision++
	a.UpdatedAt = time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE texture_assignments SET blob_digest=NULL,external_url='',active=false,visibility='private',revision=$2,updated_at=$3 WHERE id=$1`, a.ID, a.Revision, a.UpdatedAt); err != nil {
		return zero, err
	}
	event, reason := "reset", "reset to project defaults"
	if deleteAsset {
		event = "delete"
		reason = "deleted selection and removed saved item"
	}
	if err = recordTextureRevision0255(ctx, tx, a, p.UserID, event, reason); err != nil {
		return zero, err
	}
	if deleteAsset && validTextureDigest0255(oldDigest) {
		if _, err = tx.ExecContext(ctx, `DELETE FROM texture_saved_items WHERE user_id=$1 AND kind=$2 AND digest=$3`, p.UserID, kind, oldDigest); err != nil {
			return zero, err
		}
		if err = releaseTextureOwner0255(ctx, tx, p.UserID, oldDigest); err != nil {
			return zero, err
		}
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return a, nil
}

// Remove owner quota only if the user has neither saved nor selected this blob.
// GC retains physical content through its grace period, other users unchanged.
func releaseTextureOwner0255(ctx context.Context, tx *sql.Tx, userID, digest string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM texture_blob_owners o WHERE o.user_id=$1 AND o.digest=$2
 AND NOT EXISTS(SELECT 1 FROM texture_saved_items i WHERE i.user_id=o.user_id AND i.digest=o.digest)
 AND NOT EXISTS(SELECT 1 FROM texture_assignments a WHERE a.user_id=o.user_id AND a.blob_digest=o.digest)`, userID, digest)
	return err
}

func (r *SQLRepository) DeleteSavedTexture0255(ctx context.Context, p model.MinecraftProfile, kind, digest string) error {
	if err := r.check(); err != nil {
		return err
	}
	if !validTextureKind0255(kind) || !validTextureDigest0255(digest) {
		return ErrNotFound
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockOwnedTexture0255(ctx, tx, p); err != nil {
		return err
	}
	// Same advisory lock as StageTextureUpload0253; quota and removal cannot
	// race staging or finalization for this account.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(253,hashtext($1))`, p.UserID); err != nil {
		return err
	}
	var inUse bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_assignments
 WHERE user_id=$1 AND realm='local-project' AND kind=$2 AND blob_digest=$3)`, p.UserID, kind, digest).Scan(&inUse); err != nil {
		return err
	}
	if inUse {
		return ErrTextureInUse0255
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM texture_saved_items WHERE user_id=$1 AND kind=$2 AND digest=$3`, p.UserID, kind, digest)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err = releaseTextureOwner0255(ctx, tx, p.UserID, digest); err != nil {
		return err
	}
	return tx.Commit()
}

// ReadSavedTextureBlob0255 is the only preview lookup for inactive private
// library items. Neither a digest alone nor a supplied UUID grants access.
func (r *SQLRepository) ReadSavedTextureBlob0255(ctx context.Context, p model.MinecraftProfile, kind, digest string) (TextureBlob0252, bool, error) {
	var meta TextureBlob0252
	if err := r.check(); err != nil {
		return meta, false, err
	}
	if !localTextureOwner0255(p) || !validTextureKind0255(kind) || !validTextureDigest0255(digest) {
		return meta, false, nil
	}
	err := r.db.QueryRowContext(ctx, `SELECT b.digest,b.byte_size,b.storage_driver,b.object_key FROM texture_blobs b
  JOIN texture_saved_items i ON i.digest=b.digest
  JOIN texture_blob_owners o ON o.user_id=i.user_id AND o.digest=i.digest
  JOIN minecraft_profiles p ON p.user_id=i.user_id
  WHERE p.uuid=$1 AND p.user_id=$2 AND i.kind=$3 AND i.digest=$4 AND b.status='verified'`, p.UUID, p.UserID, kind, digest).
		Scan(&meta.Digest, &meta.ByteSize, &meta.StorageDriver, &meta.ObjectKey)
	if errors.Is(err, sql.ErrNoRows) {
		return meta, false, nil
	}
	return meta, err == nil, err
}

// Compile-time type assertion also enforces full implementation by SQLRepository.
var _ TextureServiceRepository0255 = (*SQLRepository)(nil)
