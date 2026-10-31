package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// TextureRepository0251 is an operational CAS store. It is intentionally separate
// from the pre-0.25.1 ServerBridge URL repository: writes overwrite legacy data.
type TextureRepository0251 interface {
	ReadTextureProfile0251(context.Context, string) (model.ServerBridgeTexture, bool, error)
	ListTextureAssignments0251(context.Context, model.MinecraftProfile) ([]model.TextureAssignment0251, error)
	UpdateTextureSelection0251(context.Context, model.MinecraftProfile, string, int64, string, string, bool) (model.TextureAssignment0251, error)
	ListTextureRevisions0251(context.Context, model.MinecraftProfile, string) ([]model.TextureRevision0251, error)
}

var ErrTextureRevisionConflict0251 = errors.New("texture revision conflict")
var ErrTextureCapeDenied0251 = errors.New("cape selection is not permitted by project policy")

const textureAssignmentSelect0251 = `SELECT id,realm,profile_uuid,user_id,project_id,launcher_profile_id,kind,COALESCE(blob_digest,''),external_url,source,model,visibility,revision,active,updated_at FROM texture_assignments`

func scanTextureAssignment0251(row interface{ Scan(...any) error }) (model.TextureAssignment0251, error) {
	var a model.TextureAssignment0251
	err := row.Scan(&a.ID, &a.Realm, &a.ProfileUUID, &a.UserID, &a.ProjectID, &a.LauncherProfileID, &a.Kind, &a.BlobDigest, &a.ExternalURL, &a.Source, &a.Model, &a.Visibility, &a.Revision, &a.Active, &a.UpdatedAt)
	return a, err
}

// canonicalUUID0251 accepts Mojang hyphenated or compact UUIDs and no other keys.
func canonicalUUID0251(raw string) (string, error) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
	if len(s) != 32 {
		return "", fmt.Errorf("invalid Minecraft UUID")
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("invalid Minecraft UUID")
		}
	}
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func (r *SQLRepository) ReadTextureProfile0251(ctx context.Context, rawUUID string) (model.ServerBridgeTexture, bool, error) {
	if err := r.check(); err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	uuid, err := canonicalUUID0251(rawUUID)
	if err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	var t model.ServerBridgeTexture
	var userID string
	// Use an arbitrary foreign UUID as a texture owner. Legacy aliases
	// only resolve mappings whose proof was established by the SQL migration.
	err = r.db.QueryRowContext(ctx, `SELECT i.profile_uuid,i.profile_name,i.user_id FROM texture_identities i
      WHERE i.realm='local-project' AND i.profile_uuid=$1
      UNION ALL
      SELECT i.profile_uuid,i.profile_name,i.user_id FROM texture_legacy_aliases a
      JOIN texture_identities i ON i.realm=a.realm AND i.profile_uuid=a.profile_uuid
      WHERE a.legacy_uuid=$1 AND i.realm='local-project' AND i.profile_uuid<>$1 LIMIT 1`, uuid).Scan(&t.UUID, &t.Username, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ServerBridgeTexture{}, false, nil
	}
	if err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	t.Model = "classic"
	// Only global public active selections are exposed to the Yggdrasil/ServerBridge path.
	rows, err := r.db.QueryContext(ctx, `SELECT kind,external_url,COALESCE(blob_digest,''),model FROM texture_assignments
      WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND active=true AND visibility='public' AND texture_permission_allowed_0259(project_id,user_id,kind) AND (blob_digest IS NULL OR EXISTS (SELECT 1 FROM texture_blobs b WHERE b.digest=blob_digest AND b.status='verified'))`, t.UUID, userID)
	if err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, url, blobDigest, skinModel string
		if err := rows.Scan(&kind, &url, &blobDigest, &skinModel); err != nil {
			return model.ServerBridgeTexture{}, false, err
		}
		if blobDigest != "" && r.publicURL != "" {
			url = r.publicURL + "/api/v1/textures/blob/" + blobDigest
		}
		if kind == "skin" {
			t.SkinURL = url
			t.Model = skinModel
		} else if kind == "cape" {
			t.CapeURL = url
		}
	}
	if err := rows.Err(); err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	if err := rows.Close(); err != nil {
		return model.ServerBridgeTexture{}, false, err
	}
	// Global defaults apply when a player has no public selection. A separate
	// fallback applies if a selected texture becomes unavailable or disallowed.
	// Both paths are restricted to verified local managed objects.
	if (t.SkinURL == "" || t.CapeURL == "") && r.publicURL != "" {
		var activeSkin, activeCape bool
		err = r.db.QueryRowContext(ctx, `SELECT
          EXISTS(SELECT 1 FROM texture_assignments WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind='skin' AND active),
          EXISTS(SELECT 1 FROM texture_assignments WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind='cape' AND active)`, t.UUID, userID).Scan(&activeSkin, &activeCape)
		if err != nil {
			return model.ServerBridgeTexture{}, false, err
		}
		var defaultSkin, defaultCape, fallbackSkin, fallbackCape, defaultModel, fallbackModel string
		err = r.db.QueryRowContext(ctx, `SELECT
         COALESCE((SELECT default_skin_model FROM texture_project_policies WHERE project_id=''),'classic'),
         COALESCE((SELECT fallback_skin_model FROM texture_project_policies WHERE project_id=''),'classic'),
         COALESCE((SELECT b.digest FROM texture_project_policies p JOIN texture_blobs b ON b.digest=p.default_skin_digest AND b.status='verified' WHERE p.project_id=''),''),
         COALESCE((SELECT b.digest FROM texture_project_policies p JOIN texture_blobs b ON b.digest=p.default_cape_digest AND b.status='verified' WHERE p.project_id=''),''),
         COALESCE((SELECT b.digest FROM texture_project_policies p JOIN texture_blobs b ON b.digest=p.fallback_skin_digest AND b.status='verified' WHERE p.project_id=''),''),
         COALESCE((SELECT b.digest FROM texture_project_policies p JOIN texture_blobs b ON b.digest=p.fallback_cape_digest AND b.status='verified' WHERE p.project_id=''),'')`).Scan(&defaultModel, &fallbackModel, &defaultSkin, &defaultCape, &fallbackSkin, &fallbackCape)
		if err != nil {
			return model.ServerBridgeTexture{}, false, err
		}
		if t.SkinURL == "" {
			digest, skinModel := defaultSkin, defaultModel
			if activeSkin && fallbackSkin != "" {
				digest, skinModel = fallbackSkin, fallbackModel
			}
			if digest != "" {
				t.SkinURL = r.publicURL + "/api/v1/textures/blob/" + digest
				t.Model = skinModel
			}
		}
		if t.CapeURL == "" {
			digest := defaultCape
			if activeCape && fallbackCape != "" {
				digest = fallbackCape
			}
			if digest != "" {
				t.CapeURL = r.publicURL + "/api/v1/textures/blob/" + digest
			}
		}
	}
	return t, true, nil
}

func (r *SQLRepository) ListTextureAssignments0251(ctx context.Context, profile model.MinecraftProfile) ([]model.TextureAssignment0251, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, textureAssignmentSelect0251+` WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 ORDER BY project_id,kind`, profile.UUID, profile.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.TextureAssignment0251, 0)
	for rows.Next() {
		a, err := scanTextureAssignment0251(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func validateTextureSelection0251(kind, skinModel, visibility string) error {
	if kind != "skin" && kind != "cape" {
		return fmt.Errorf("unsupported texture kind")
	}
	if skinModel != "classic" && skinModel != "slim" {
		return fmt.Errorf("unsupported skin model")
	}
	if kind == "cape" && skinModel != "classic" {
		return fmt.Errorf("cape cannot use slim model")
	}
	if visibility != "public" && visibility != "private" && visibility != "unlisted" {
		return fmt.Errorf("unsupported visibility")
	}
	return nil
}

// UpdateTextureSelection0251 serializes competing writers per assignment and
// records the complete new state in the SAME transaction as its revision bump.
func (r *SQLRepository) UpdateTextureSelection0251(ctx context.Context, profile model.MinecraftProfile, kind string, expected int64, skinModel, visibility string, active bool) (model.TextureAssignment0251, error) {
	if err := r.check(); err != nil {
		return model.TextureAssignment0251{}, err
	}
	if err := validateTextureSelection0251(kind, skinModel, visibility); err != nil {
		return model.TextureAssignment0251{}, err
	}
	if expected < 1 {
		return model.TextureAssignment0251{}, ErrTextureRevisionConflict0251
	}
	if profile.Realm != "local" || profile.Issuer != "launcher" {
		return model.TextureAssignment0251{}, fmt.Errorf("official identity cannot be changed via local texture service")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return model.TextureAssignment0251{}, err
	}
	defer tx.Rollback()
	// Prove UUID and user ownership in PostgreSQL; caller-supplied profile UUID
	// alone authorizes mutation. New Minecraft profiles sync lazily.
	res, err := tx.ExecContext(ctx, `INSERT INTO texture_identities(realm,profile_uuid,user_id,profile_name,origin,local_profile_uuid)
      SELECT 'local-project',uuid,user_id,name,'local-profile',uuid FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2
      ON CONFLICT(realm,profile_uuid) DO UPDATE SET profile_name=EXCLUDED.profile_name
      WHERE texture_identities.user_id=EXCLUDED.user_id`, profile.UUID, profile.UserID)
	if err != nil {
		return model.TextureAssignment0251{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return model.TextureAssignment0251{}, ErrNotFound
	}
	a, err := scanTextureAssignment0251(tx.QueryRowContext(ctx, textureAssignmentSelect0251+` WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2 AND project_id='' AND kind=$3 FOR UPDATE`, profile.UUID, profile.UserID, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return model.TextureAssignment0251{}, ErrNotFound
	}
	if err != nil {
		return model.TextureAssignment0251{}, err
	}
	if a.Revision != expected {
		return model.TextureAssignment0251{}, ErrTextureRevisionConflict0251
	}
	if active && a.BlobDigest == "" && a.ExternalURL == "" {
		return model.TextureAssignment0251{}, ErrTextureNotSelected0255
	}
	if kind == "skin" && active {
		var permitted bool
		if err = tx.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259($1,$2,'skin')`, a.ProjectID, a.UserID).Scan(&permitted); err != nil {
			return model.TextureAssignment0251{}, err
		}
		if !permitted {
			return model.TextureAssignment0251{}, ErrTextureUploadDenied0252
		}
	}
	if kind == "cape" && active {
		var permitted bool
		// Existing legacy CAPE URLs can be read for compatibility, but a user
		// cannot newly activate or re-publish them without a project grant.
		err = tx.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259($1,$2,'cape')`, a.ProjectID, a.UserID).Scan(&permitted)
		if err != nil {
			return model.TextureAssignment0251{}, err
		}
		if !permitted {
			return model.TextureAssignment0251{}, ErrTextureCapeDenied0251
		}
	}
	oldModel, oldVisibility, oldActive := a.Model, a.Visibility, a.Active
	if !active {
		visibility = "private"
	} // reset unintentionally republishes old URL
	a.Model = skinModel
	a.Visibility = visibility
	a.Active = active
	a.Revision++
	a.UpdatedAt = time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE texture_assignments SET model=$2,visibility=$3,active=$4,revision=$5,updated_at=$6 WHERE id=$1`, a.ID, a.Model, a.Visibility, a.Active, a.Revision, a.UpdatedAt); err != nil {
		return model.TextureAssignment0251{}, err
	}
	snapshot, err := json.Marshal(map[string]any{"blobDigest": a.BlobDigest, "externalUrl": a.ExternalURL, "kind": a.Kind, "model": a.Model, "visibility": a.Visibility, "active": a.Active, "source": a.Source, "projectId": a.ProjectID})
	if err != nil {
		return model.TextureAssignment0251{}, err
	}
	event := "select"
	if !active {
		event = "reset"
	} else if oldModel != skinModel {
		event = "model-change"
	} else if oldVisibility != visibility {
		event = "visibility-change"
	} else if !oldActive {
		event = "select"
	} // remaining state is in snapshot
	if _, err := tx.ExecContext(ctx, `INSERT INTO texture_assignment_revisions(assignment_id,revision,snapshot,actor_user_id,reason,event) VALUES($1,$2,$3,$4,$5,$6)`, a.ID, a.Revision, snapshot, a.UserID, "player selection update", event); err != nil {
		return model.TextureAssignment0251{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.TextureAssignment0251{}, err
	}
	return a, nil
}

func (r *SQLRepository) ListTextureRevisions0251(ctx context.Context, profile model.MinecraftProfile, kind string) ([]model.TextureRevision0251, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if kind != "skin" && kind != "cape" {
		return nil, fmt.Errorf("unsupported kind")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT v.assignment_id,v.revision,v.snapshot,v.actor_user_id,v.reason,v.event,v.created_at
      FROM texture_assignment_revisions v JOIN texture_assignments a ON a.id=v.assignment_id
      WHERE a.realm='local-project' AND a.profile_uuid=$1 AND a.user_id=$2 AND a.kind=$3
      ORDER BY v.revision DESC LIMIT 100`, profile.UUID, profile.UserID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.TextureRevision0251, 0)
	for rows.Next() {
		var v model.TextureRevision0251
		if err := rows.Scan(&v.AssignmentID, &v.Revision, &v.Snapshot, &v.ActorUserID, &v.Reason, &v.Event, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// EnsureTextureIdentity0251 atomically binds legacy user-derived URLs to an
// already-proven canonical profile. Called when a profile is loaded/created,
// including accounts that had URL records but no Minecraft profile at migration.
func (r *SQLRepository) EnsureTextureIdentity0251(ctx context.Context, profile model.MinecraftProfile) error {
	if err := r.check(); err != nil {
		return err
	}
	if profile.Realm != "local" || profile.Issuer != "launcher" {
		return fmt.Errorf("not a local Minecraft profile")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serializes lazy imports and protects revision 1 against concurrent calls.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(251,hashtext($1))`, profile.UUID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO texture_identities(realm,profile_uuid,user_id,profile_name,origin,local_profile_uuid)
      SELECT 'local-project',uuid,user_id,name,'local-profile',uuid FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2
      ON CONFLICT(realm,profile_uuid) DO UPDATE SET profile_name=EXCLUDED.profile_name
      WHERE texture_identities.user_id=EXCLUDED.user_id`, profile.UUID, profile.UserID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return ErrNotFound
	}
	digest := sha256.Sum256([]byte("launcher-player:" + profile.UserID))
	raw := hex.EncodeToString(digest[:16])
	legacy := raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
	for _, candidate := range []struct{ key, mapping string }{{strings.ToLower(profile.UUID), "exact"}, {legacy, "user-derived-v2"}} {
		_, err = tx.ExecContext(ctx, `INSERT INTO texture_legacy_aliases(legacy_uuid,realm,profile_uuid,user_id,mapping)
          VALUES($1,'local-project',$2,$3,$4) ON CONFLICT(legacy_uuid) DO NOTHING`, candidate.key, profile.UUID, profile.UserID, candidate.mapping)
		if err != nil {
			return err
		}
		// A colliding alias must be allowed to reassign another user's texture.
		var owner, uuid string
		if err = tx.QueryRowContext(ctx, `SELECT user_id,profile_uuid FROM texture_legacy_aliases WHERE legacy_uuid=$1`, candidate.key).Scan(&owner, &uuid); err != nil {
			return err
		}
		if owner != profile.UserID || uuid != profile.UUID {
			return ErrConflict
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,external_url,source,model,visibility,updated_at)
      SELECT 'local-project',$1,$2,k.kind,k.url,'remote-reference',
      CASE WHEN k.kind='skin' AND t.model='slim' THEN 'slim' ELSE 'classic' END,'public',t.updated_at
      FROM server_bridge_textures_v2 t
      CROSS JOIN LATERAL (VALUES ('skin',t.skin_url),('cape',t.cape_url)) k(kind,url)
      WHERE lower(t.player_uuid) IN ($1,$3) AND k.url<>''
      ON CONFLICT(realm,profile_uuid,project_id,kind) DO NOTHING`, profile.UUID, profile.UserID, legacy)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO texture_assignment_revisions(assignment_id,revision,snapshot,actor_user_id,reason,event)
      SELECT id,revision,jsonb_build_object('source',source,'kind',kind,'externalUrl',external_url,'model',model,'visibility',visibility,'active',active,'projectId',project_id,'blobDigest',blob_digest),user_id,
      '0.25.0 lazy ServerBridge URL migration','legacy-import' FROM texture_assignments WHERE realm='local-project' AND profile_uuid=$1 AND user_id=$2
      ON CONFLICT(assignment_id,revision) DO NOTHING`, profile.UUID, profile.UserID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM texture_legacy_unmatched WHERE lower(legacy_uuid) IN ($1,$2)`, strings.ToLower(profile.UUID), legacy); err != nil {
		return err
	}
	return tx.Commit()
}
