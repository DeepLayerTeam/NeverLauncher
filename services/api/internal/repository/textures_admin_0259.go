package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrTexturePolicyConflict0259 = errors.New("texture policy revision conflict")
var ErrTexturePolicyInvalid0259 = errors.New("invalid texture policy")

type TexturePolicy0259 struct {
	ProjectID          string    `json:"projectId"`
	Revision           int64     `json:"revision"`
	AllowPlayerSkins   bool      `json:"allowPlayerSkins"`
	AllowPlayerCapes   bool      `json:"allowPlayerCapes"`
	DefaultSkinModel   string    `json:"defaultSkinModel"`
	DefaultSkinDigest  string    `json:"defaultSkinDigest"`
	DefaultCapeDigest  string    `json:"defaultCapeDigest"`
	FallbackSkinModel  string    `json:"fallbackSkinModel"`
	FallbackSkinDigest string    `json:"fallbackSkinDigest"`
	FallbackCapeDigest string    `json:"fallbackCapeDigest"`
	MaxBytesPerPlayer  int64     `json:"maxBytesPerPlayer"`
	MaxBlobsPerPlayer  int       `json:"maxBlobsPerPlayer"`
	UpdatedAt          time.Time `json:"updatedAt,omitempty"`
}
type TexturePolicyChange0259 struct {
	ExpectedRevision int64             `json:"expectedRevision"`
	Policy           TexturePolicy0259 `json:"policy"`
	Reason           string            `json:"reason"`
}
type TextureException0259 struct {
	UserID      string    `json:"userId"`
	Kind        string    `json:"kind"`
	Decision    string    `json:"decision"` // allow, deny or inherit (delete)
	Reason      string    `json:"reason"`
	ActorUserID string    `json:"actorUserId,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"`
}
type TextureAudit0259 struct {
	ID          int64           `json:"id"`
	Revision    int64           `json:"revision,omitempty"`
	UserID      string          `json:"userId,omitempty"`
	Kind        string          `json:"kind,omitempty"`
	From        string          `json:"from,omitempty"`
	To          string          `json:"to,omitempty"`
	Snapshot    json.RawMessage `json:"snapshot,omitempty"`
	ActorUserID string          `json:"actorUserId"`
	Reason      string          `json:"reason"`
	CreatedAt   time.Time       `json:"createdAt"`
}
type TextureDefaultOption0259 struct {
	Digest string `json:"digest"`
	Kind   string `json:"kind"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Bytes  int64  `json:"bytes"`
}
type TextureAdminRepository0259 interface {
	GetTexturePolicy0259(context.Context, string) (TexturePolicy0259, error)
	SaveTexturePolicy0259(context.Context, string, TexturePolicyChange0259, string) (TexturePolicy0259, error)
	ListTexturePolicyHistory0259(context.Context, string) ([]TextureAudit0259, error)
	ListTextureExceptions0259(context.Context, string, string) ([]TextureException0259, error)
	SetTextureException0259(context.Context, string, string, TextureException0259, string) error
	ListTextureExceptionHistory0259(context.Context, string) ([]TextureAudit0259, error)
	ListTextureDefaultOptions0259(context.Context, string) ([]TextureDefaultOption0259, error)
	ListTexturePlayerHistory0259(context.Context, string, string) ([]TexturePlayerChange0259, error)
}

func policyDefault0259(project string) TexturePolicy0259 {
	return TexturePolicy0259{ProjectID: project, Revision: 0, AllowPlayerSkins: true, DefaultSkinModel: "classic", FallbackSkinModel: "classic", MaxBytesPerPlayer: 10485760, MaxBlobsPerPlayer: 20}
}
func validProject0259(ctx context.Context, tx *sql.Tx, project string) error {
	if project == "" {
		return nil
	}
	if len(project) > 128 || strings.ContainsAny(project, "\x00\r\n") {
		return ErrTexturePolicyInvalid0259
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, project).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}
func readPolicy0259(ctx context.Context, tx *sql.Tx, project string, lock bool) (TexturePolicy0259, error) {
	p := policyDefault0259(project)
	query := `SELECT revision,allow_player_skins,allow_player_capes,default_skin_model,COALESCE(default_skin_digest,''),COALESCE(default_cape_digest,''),fallback_skin_model,COALESCE(fallback_skin_digest,''),COALESCE(fallback_cape_digest,''),max_bytes_per_player,max_blobs_per_player,updated_at FROM texture_project_policies WHERE project_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	err := tx.QueryRowContext(ctx, query, project).Scan(&p.Revision, &p.AllowPlayerSkins, &p.AllowPlayerCapes, &p.DefaultSkinModel, &p.DefaultSkinDigest, &p.DefaultCapeDigest, &p.FallbackSkinModel, &p.FallbackSkinDigest, &p.FallbackCapeDigest, &p.MaxBytesPerPlayer, &p.MaxBlobsPerPlayer, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	return p, err
}
func (r *SQLRepository) GetTexturePolicy0259(ctx context.Context, project string) (TexturePolicy0259, error) {
	if err := r.check(); err != nil {
		return TexturePolicy0259{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TexturePolicy0259{}, err
	}
	defer tx.Rollback()
	if err = validProject0259(ctx, tx, project); err != nil {
		return TexturePolicy0259{}, err
	}
	p, err := readPolicy0259(ctx, tx, project, false)
	if err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func validatedDigest0259(ctx context.Context, tx *sql.Tx, project, kind, digest string) error {
	if digest == "" {
		return nil
	}
	if !validTextureDigest0255(digest) {
		return ErrTexturePolicyInvalid0259
	}
	// Admin cannot expose private player assets as a public project default.
	// Only already-public, currently-active, verified PNGs of this kind may become defaults.
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_blobs b JOIN texture_assignments a ON a.blob_digest=b.digest
 WHERE b.digest=$1 AND b.status='verified' AND a.kind=$2 AND a.realm='local-project'
 AND a.active AND a.visibility='public' AND a.project_id=$3)`, digest, kind, project).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrTexturePolicyInvalid0259
	}
	return nil
}
func (r *SQLRepository) SaveTexturePolicy0259(ctx context.Context, project string, change TexturePolicyChange0259, actor string) (TexturePolicy0259, error) {
	var zero TexturePolicy0259
	if err := r.check(); err != nil {
		return zero, err
	}
	input := change.Policy
	if (input.DefaultSkinModel != "classic" && input.DefaultSkinModel != "slim") || (input.FallbackSkinModel != "classic" && input.FallbackSkinModel != "slim") || change.ExpectedRevision < 0 || len(strings.TrimSpace(change.Reason)) < 3 || len(change.Reason) > 500 || input.MaxBytesPerPlayer < 1024 || input.MaxBytesPerPlayer > 1073741824 || input.MaxBlobsPerPlayer < 1 || input.MaxBlobsPerPlayer > 10000 || actor == "" {
		return zero, ErrTexturePolicyInvalid0259
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err = validProject0259(ctx, tx, project); err != nil {
		return zero, err
	}
	// Serialize initial creation and policy changes for the same project.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(259,hashtext($1))`, project); err != nil {
		return zero, err
	}
	old, err := readPolicy0259(ctx, tx, project, true)
	if err != nil {
		return zero, err
	}
	if old.Revision != change.ExpectedRevision {
		return zero, ErrTexturePolicyConflict0259
	}
	for _, d := range []struct{ kind, digest string }{{"skin", input.DefaultSkinDigest}, {"cape", input.DefaultCapeDigest}, {"skin", input.FallbackSkinDigest}, {"cape", input.FallbackCapeDigest}} {
		if err = validatedDigest0259(ctx, tx, project, d.kind, d.digest); err != nil {
			return zero, err
		}
	}
	if old.Revision == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO texture_project_policies(project_id,allow_player_skins,allow_player_capes,default_skin_digest,default_cape_digest,default_skin_model,fallback_skin_digest,fallback_cape_digest,fallback_skin_model,max_bytes_per_player,max_blobs_per_player,revision,actor_user_id,reason)
 VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$10,NULLIF($11,''),NULLIF($12,''),$13,$6,$7,1,$8,$9)`, project, input.AllowPlayerSkins, input.AllowPlayerCapes, input.DefaultSkinDigest, input.DefaultCapeDigest, input.MaxBytesPerPlayer, input.MaxBlobsPerPlayer, actor, change.Reason, input.DefaultSkinModel, input.FallbackSkinDigest, input.FallbackCapeDigest, input.FallbackSkinModel)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE texture_project_policies SET allow_player_skins=$2,allow_player_capes=$3,default_skin_digest=NULLIF($4,''),default_cape_digest=NULLIF($5,''),max_bytes_per_player=$6,max_blobs_per_player=$7,default_skin_model=$10,fallback_skin_digest=NULLIF($11,''),fallback_cape_digest=NULLIF($12,''),fallback_skin_model=$13,revision=revision+1,actor_user_id=$8,reason=$9,updated_at=now() WHERE project_id=$1`, project, input.AllowPlayerSkins, input.AllowPlayerCapes, input.DefaultSkinDigest, input.DefaultCapeDigest, input.MaxBytesPerPlayer, input.MaxBlobsPerPlayer, actor, change.Reason, input.DefaultSkinModel, input.FallbackSkinDigest, input.FallbackCapeDigest, input.FallbackSkinModel)
	}
	if err != nil {
		return zero, err
	}
	updated, err := readPolicy0259(ctx, tx, project, false)
	if err != nil {
		return zero, err
	}
	snapshot, err := json.Marshal(updated)
	if err != nil {
		return zero, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO texture_policy_history(project_id,revision,snapshot,actor_user_id,reason) VALUES($1,$2,$3,$4,$5)`, project, updated.Revision, snapshot, actor, change.Reason)
	if err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return updated, nil
}
func (r *SQLRepository) ListTexturePolicyHistory0259(ctx context.Context, project string) ([]TextureAudit0259, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,revision,snapshot,actor_user_id,reason,created_at FROM texture_policy_history WHERE project_id=$1 ORDER BY id DESC LIMIT 100`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureAudit0259, 0)
	for rows.Next() {
		var a TextureAudit0259
		if err = rows.Scan(&a.ID, &a.Revision, &a.Snapshot, &a.ActorUserID, &a.Reason, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ListTextureExceptions0259(ctx context.Context, project, user string) ([]TextureException0259, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT user_id,kind,decision,reason,actor_user_id,updated_at FROM texture_user_exceptions WHERE project_id=$1 AND ($2='' OR user_id=$2) ORDER BY user_id,kind LIMIT 500`, project, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureException0259, 0)
	for rows.Next() {
		var v TextureException0259
		if err = rows.Scan(&v.UserID, &v.Kind, &v.Decision, &v.Reason, &v.ActorUserID, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (r *SQLRepository) SetTextureException0259(ctx context.Context, project, user string, in TextureException0259, actor string) error {
	if err := r.check(); err != nil {
		return err
	}
	if user == "" || len(user) > 128 || (in.Kind != "skin" && in.Kind != "cape") || (in.Decision != "allow" && in.Decision != "deny" && in.Decision != "inherit") || len(strings.TrimSpace(in.Reason)) < 3 || len(in.Reason) > 500 || actor == "" {
		return ErrTexturePolicyInvalid0259
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = validProject0259(ctx, tx, project); err != nil {
		return err
	}
	var found bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, user).Scan(&found); err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(259,hashtext($1))`, project+":"+user+":"+in.Kind); err != nil {
		return err
	}
	var old string
	err = tx.QueryRowContext(ctx, `SELECT decision FROM texture_user_exceptions WHERE project_id=$1 AND user_id=$2 AND kind=$3 FOR UPDATE`, project, user, in.Kind).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) {
		old = "inherit"
	} else if err != nil {
		return err
	}
	if in.Decision == "inherit" {
		_, err = tx.ExecContext(ctx, `DELETE FROM texture_user_exceptions WHERE project_id=$1 AND user_id=$2 AND kind=$3`, project, user, in.Kind)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO texture_user_exceptions(project_id,user_id,kind,decision,actor_user_id,reason) VALUES($1,$2,$3,$4,$5,$6)
   ON CONFLICT(project_id,user_id,kind) DO UPDATE SET decision=EXCLUDED.decision,actor_user_id=EXCLUDED.actor_user_id,reason=EXCLUDED.reason,updated_at=now()`, project, user, in.Kind, in.Decision, actor, in.Reason)
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO texture_exception_history(project_id,user_id,kind,old_decision,new_decision,actor_user_id,reason) VALUES($1,$2,$3,$4,$5,$6,$7)`, project, user, in.Kind, old, in.Decision, actor, in.Reason)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (r *SQLRepository) ListTextureExceptionHistory0259(ctx context.Context, project string) ([]TextureAudit0259, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,user_id,kind,old_decision,new_decision,actor_user_id,reason,created_at FROM texture_exception_history WHERE project_id=$1 ORDER BY id DESC LIMIT 100`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureAudit0259, 0)
	for rows.Next() {
		var a TextureAudit0259
		if err = rows.Scan(&a.ID, &a.UserID, &a.Kind, &a.From, &a.To, &a.ActorUserID, &a.Reason, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (r *SQLRepository) ListTextureDefaultOptions0259(ctx context.Context, project string) ([]TextureDefaultOption0259, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT b.digest,a.kind,b.width,b.height,b.byte_size FROM texture_blobs b JOIN texture_assignments a ON a.blob_digest=b.digest
 WHERE b.status='verified' AND a.realm='local-project' AND a.project_id=$1 AND a.active AND a.visibility='public' ORDER BY a.kind,b.digest LIMIT 200`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TextureDefaultOption0259, 0)
	for rows.Next() {
		var a TextureDefaultOption0259
		if err = rows.Scan(&a.Digest, &a.Kind, &a.Width, &a.Height, &a.Bytes); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

var _ TextureAdminRepository0259 = (*SQLRepository)(nil)

// TexturePlayerChange0259 is a history entry for an actual player skin/cape
// assignment. It is distinct from administrator policy/exception history.
type TexturePlayerChange0259 struct {
	ProfileUUID string          `json:"profileUuid"`
	Kind        string          `json:"kind"`
	Revision    int64           `json:"revision"`
	Event       string          `json:"event"`
	Snapshot    json.RawMessage `json:"snapshot"`
	ActorUserID string          `json:"actorUserId"`
	Reason      string          `json:"reason"`
	CreatedAt   time.Time       `json:"createdAt"`
}

func (r *SQLRepository) ListTexturePlayerHistory0259(ctx context.Context, project, user string) ([]TexturePlayerChange0259, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if user == "" || len(user) > 128 {
		return nil, ErrTexturePolicyInvalid0259
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.profile_uuid,a.kind,r.revision,r.event,r.snapshot,r.actor_user_id,r.reason,r.created_at
 FROM texture_assignment_revisions r JOIN texture_assignments a ON a.id=r.assignment_id
 WHERE a.realm='local-project' AND a.user_id=$1 AND a.project_id=$2
 ORDER BY r.created_at DESC,a.id DESC,r.revision DESC LIMIT 100`, user, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TexturePlayerChange0259, 0)
	for rows.Next() {
		var v TexturePlayerChange0259
		if err = rows.Scan(&v.ProfileUUID, &v.Kind, &v.Revision, &v.Event, &v.Snapshot, &v.ActorUserID, &v.Reason, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
