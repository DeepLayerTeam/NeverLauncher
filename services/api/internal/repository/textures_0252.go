package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// VerifiedTexture0252 is constructed only from a fully decoded and normalized
// PNG and from the successful storage write performed by the HTTP service.
type VerifiedTexture0252 struct {
	Digest                  string
	Width, Height           int
	Size                    int64
	Driver, ObjectKey       string
	Kind, Model, Visibility string
	Source                  string // managed-upload or managed-url-import
	ExpectedRevision        int64  // 0 means create-only; >0 means CAS replacement
}

type TextureBlob0252 struct {
	Digest        string
	ByteSize      int64
	StorageDriver string
	ObjectKey     string
}

type TextureUploadRepository0252 interface {
	UploadTexture0252(context.Context, model.MinecraftProfile, VerifiedTexture0252) (model.TextureAssignment0251, error)
	ReadTextureBlob0252(context.Context, string, model.MinecraftProfile, bool) (TextureBlob0252, bool, error)
}

var ErrTextureUploadDenied0252 = errors.New("texture upload forbidden by policy")
var ErrTextureUploadLimit0252 = errors.New("texture size exceeds project policy")

func (r *SQLRepository) UploadTexture0252(ctx context.Context, profile model.MinecraftProfile, input VerifiedTexture0252) (model.TextureAssignment0251, error) {
	var zero model.TextureAssignment0251
	if err := r.check(); err != nil {
		return zero, err
	}
	if profile.Realm != "local" || profile.Issuer != "neverlauncher" || profile.UserID == "" {
		return zero, ErrNotFound
	}
	source := input.Source
	if source == "" {
		source = "managed-upload"
	}
	if source != "managed-upload" && source != "managed-url-import" {
		return zero, fmt.Errorf("invalid texture source")
	}
	if err := validateTextureSelection0251(input.Kind, input.Model, input.Visibility); err != nil {
		return zero, err
	}
	if input.ExpectedRevision < 0 || input.Size < 1 || input.Size > 4<<20 || input.Width < 64 || input.Height < 32 || input.Width > 1024 || input.Height > 1024 || len(input.Digest) != 64 {
		return zero, fmt.Errorf("invalid verified PNG")
	}
	if input.Driver != "local" && input.Driver != "s3" {
		return zero, fmt.Errorf("invalid storage driver")
	}
	if !strings.HasPrefix(input.ObjectKey, "texture-blobs/sha256/"+input.Digest[:2]+"/") || !strings.HasSuffix(input.ObjectKey, "/"+input.Digest+".png") {
		return zero, fmt.Errorf("invalid texture object key")
	}
	for _, c := range input.Digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return zero, fmt.Errorf("invalid blob digest")
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	// Every upload is authorized against the server-side Minecraft profile row.
	// A transaction-scoped lock serializes the create-only path as well as CAS.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(252,hashtext($1))`, profile.UUID); err != nil {
		return zero, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO texture_identities(realm,profile_uuid,user_id,profile_name,origin,local_profile_uuid)
      SELECT 'local-project',uuid,user_id,name,'local-profile',uuid FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2
      ON CONFLICT(realm,profile_uuid) DO UPDATE SET profile_name=EXCLUDED.profile_name WHERE texture_identities.user_id=EXCLUDED.user_id`, profile.UUID, profile.UserID)
	if err != nil {
		return zero, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return zero, ErrNotFound
	}
	var allowSkin, allowCape bool
	var maxBytes int64
	var maxBlobs int
	if err = tx.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('', $1, 'skin'),
       texture_permission_allowed_0259('', $1, 'cape'),
       COALESCE((SELECT max_bytes_per_player FROM texture_project_policies WHERE project_id=''),10485760),
       COALESCE((SELECT max_blobs_per_player FROM texture_project_policies WHERE project_id=''),20)`, profile.UserID).Scan(&allowSkin, &allowCape, &maxBytes, &maxBlobs); err != nil {
		return zero, err
	}
	if (input.Kind == "skin" && !allowSkin) || (input.Kind == "cape" && !allowCape) {
		return zero, ErrTextureUploadDenied0252
	}
	if input.Size > maxBytes {
		return zero, ErrTextureUploadLimit0252
	}
	// Serialize ALL profile uploads of this user (including different kinds)
	// before quota accounting. The unique owner relation prevents double charge
	// for reusing the same digest, even when many users share the blob.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(253,hashtext($1))`, profile.UserID); err != nil {
		return zero, err
	}
	var count int
	var used int64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(b.byte_size),0)
	  FROM texture_blob_owners o JOIN texture_blobs b ON b.digest=o.digest
	  WHERE o.user_id=$1`, profile.UserID).Scan(&count, &used); err != nil {
		return zero, err
	}
	var owned bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_blob_owners WHERE user_id=$1 AND digest=$2)`, profile.UserID, input.Digest).Scan(&owned); err != nil {
		return zero, err
	}
	if !owned && (count >= maxBlobs || used > maxBytes-input.Size) {
		return zero, ErrTextureUploadLimit0252
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_blobs(digest,byte_size,width,height,media_type,storage_driver,object_key,status,verified_at)
      VALUES($1,$2,$3,$4,'image/png',$5,$6,'verified',now()) ON CONFLICT(digest) DO NOTHING`, input.Digest, input.Size, input.Width, input.Height, input.Driver, input.ObjectKey); err != nil {
		return zero, err
	}
	// The object is now durably persisted: promote its pre-upload staging row.
	// This update is bounded by the verified digest metadata and never promotes
	// a GC-quarantined or mismatched object.
	if _, err = tx.ExecContext(ctx, `UPDATE texture_blobs SET status='verified',verified_at=now()
	    WHERE digest=$1 AND status='staging' AND byte_size=$2 AND storage_driver=$3 AND object_key=$4`,
		input.Digest, input.Size, input.Driver, input.ObjectKey); err != nil {
		return zero, err
	}
	// Do not silently attach an existing digest with inconsistent storage metadata.
	var existing TextureBlob0252
	if err = tx.QueryRowContext(ctx, `SELECT digest,byte_size,storage_driver,object_key FROM texture_blobs WHERE digest=$1 AND status='verified'`, input.Digest).Scan(&existing.Digest, &existing.ByteSize, &existing.StorageDriver, &existing.ObjectKey); err != nil {
		return zero, err
	}
	if existing.ByteSize != input.Size || existing.StorageDriver != input.Driver || existing.ObjectKey != input.ObjectKey {
		return zero, fmt.Errorf("blob storage metadata mismatch")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_blob_owners(user_id,digest) VALUES($1,$2) ON CONFLICT DO NOTHING`, profile.UserID, input.Digest); err != nil {
		return zero, err
	}
	assignment, err := scanTextureAssignment0251(tx.QueryRowContext(ctx, textureAssignmentSelect0251+` WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind=$3 FOR UPDATE`, profile.UUID, profile.UserID, input.Kind))
	now := time.Now().UTC()
	if errors.Is(err, sql.ErrNoRows) {
		if input.ExpectedRevision != 0 {
			return zero, ErrTextureRevisionConflict0251
		}
		assignment, err = scanTextureAssignment0251(tx.QueryRowContext(ctx, `INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,blob_digest,source,model,visibility,revision,active,updated_at)
          VALUES('local-project',$1,$2,$3,$4,$5,$6,$7,1,true,$8) RETURNING id,realm,profile_uuid,user_id,project_id,launcher_profile_id,kind,COALESCE(blob_digest,''),external_url,source,model,visibility,revision,active,updated_at`, profile.UUID, profile.UserID, input.Kind, input.Digest, source, input.Model, input.Visibility, now))
		if err != nil {
			return zero, err
		}
	} else {
		if err != nil {
			return zero, err
		}
		if assignment.Revision != input.ExpectedRevision {
			return zero, ErrTextureRevisionConflict0251
		}
		assignment.Revision++
		assignment.BlobDigest = input.Digest
		assignment.ExternalURL = ""
		assignment.Source = source
		assignment.Model = input.Model
		assignment.Visibility = input.Visibility
		assignment.Active = true
		assignment.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE texture_assignments SET blob_digest=$2,external_url='',source=$3,model=$4,visibility=$5,active=true,revision=$6,updated_at=$7 WHERE id=$1`, assignment.ID, input.Digest, source, input.Model, input.Visibility, assignment.Revision, now); err != nil {
			return zero, err
		}
	}
	// Upload and URL import make the normalized PNG reusable immediately. Keep
	// saved library membership in the SAME transaction as assignment and CAS.
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_saved_items(user_id,digest,kind,model,source,last_selected_at)
      VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id,digest,kind)
      DO UPDATE SET model=EXCLUDED.model,source=EXCLUDED.source,last_selected_at=EXCLUDED.last_selected_at`,
		profile.UserID, input.Digest, input.Kind, input.Model, source, now); err != nil {
		return zero, err
	}
	snapshot, err := json.Marshal(map[string]any{"blobDigest": input.Digest, "externalUrl": "", "kind": input.Kind, "model": input.Model, "visibility": input.Visibility, "active": true, "source": source, "projectId": ""})
	if err != nil {
		return zero, err
	}
	event := "upload"
	if source == "managed-url-import" {
		event = "import"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_assignment_revisions(assignment_id,revision,snapshot,actor_user_id,reason,event)
      VALUES($1,$2,$3,$4,$5,$6)`, assignment.ID, assignment.Revision, snapshot, profile.UserID, "verified normalized PNG "+event, event); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return assignment, nil
}

// ReadTextureBlob0252 exposes only an active public selection or an explicitly
// authenticated owner. No arbitrary digest disclosure to unauthenticated users.
func (r *SQLRepository) ReadTextureBlob0252(ctx context.Context, digest string, profile model.MinecraftProfile, owner bool) (TextureBlob0252, bool, error) {
	var b TextureBlob0252
	if err := r.check(); err != nil {
		return b, false, err
	}
	if len(digest) != 64 {
		return b, false, nil
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return b, false, nil
		}
	}
	query := `SELECT b.digest,b.byte_size,b.storage_driver,b.object_key FROM texture_blobs b
 WHERE b.digest=$1 AND b.status='verified' AND (
  EXISTS(SELECT 1 FROM texture_assignments a WHERE a.blob_digest=b.digest AND a.realm='local-project'
    AND a.active AND a.visibility='public' AND texture_permission_allowed_0259(a.project_id,a.user_id,a.kind))
  OR EXISTS(SELECT 1 FROM texture_project_policies p WHERE p.project_id='' AND (p.default_skin_digest=b.digest OR p.default_cape_digest=b.digest OR p.fallback_skin_digest=b.digest OR p.fallback_cape_digest=b.digest))
 )`
	var err error
	if owner {
		if profile.Realm != "local" || profile.Issuer != "neverlauncher" {
			return b, false, nil
		}
		query = `SELECT b.digest,b.byte_size,b.storage_driver,b.object_key FROM texture_blobs b
          WHERE b.digest=$1 AND b.status='verified' AND EXISTS (SELECT 1 FROM texture_assignments a
          WHERE a.blob_digest=b.digest AND a.realm='local-project' AND a.profile_uuid=$2 AND a.user_id=$3)`
		err = r.db.QueryRowContext(ctx, query, digest, profile.UUID, profile.UserID).Scan(&b.Digest, &b.ByteSize, &b.StorageDriver, &b.ObjectKey)
	} else {
		err = r.db.QueryRowContext(ctx, query, digest).Scan(&b.Digest, &b.ByteSize, &b.StorageDriver, &b.ObjectKey)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return b, false, nil
	}
	return b, err == nil, err
}
