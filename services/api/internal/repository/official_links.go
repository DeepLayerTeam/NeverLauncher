package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OfficialNeverLink0268 is a persistent verified relationship, not an auth credential.
// A Never identity may link multiple Minecraft UUIDs; a UUID has one owner globally.
type OfficialNeverLink0268 struct {
	MinecraftUUID string    `json:"minecraftUuid"`
	MinecraftName string    `json:"minecraftName"`
	VerifiedAt    time.Time `json:"verifiedAt"`
}

var ErrOfficialLinkOwned0268 = errors.New("Minecraft account already linked to another Never identity")
var ErrOfficialLinkAbsent0268 = errors.New("Minecraft account is not linked to this Never identity")

type OfficialLinkStore0268 interface {
	ListOfficialLinks0268(context.Context, string) ([]OfficialNeverLink0268, error)
	UpsertOfficialLink0268(context.Context, string, string, string) (OfficialNeverLink0268, error)
	RemoveOfficialLink0268(context.Context, string, string) error
}

func (r *SQLRepository) ListOfficialLinks0268(ctx context.Context, owner string) ([]OfficialNeverLink0268, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT minecraft_uuid,minecraft_name,verified_at FROM official_identity_links_0268 WHERE user_id=$1 ORDER BY created_at,minecraft_uuid`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]OfficialNeverLink0268, 0)
	for rows.Next() {
		var x OfficialNeverLink0268
		if err := rows.Scan(&x.MinecraftUUID, &x.MinecraftName, &x.VerifiedAt); err != nil {
			return nil, err
		}
		result = append(result, x)
	}
	return result, rows.Err()
}

func (r *SQLRepository) UpsertOfficialLink0268(ctx context.Context, owner, uuid, name string) (OfficialNeverLink0268, error) {
	if err := r.check(); err != nil {
		return OfficialNeverLink0268{}, err
	}
	// Conditional upsert is atomic across all Backend instances. An owner cannot
	// take over another owner's Minecraft identity through a racing POST.
	var result OfficialNeverLink0268
	err := r.db.QueryRowContext(ctx, `INSERT INTO official_identity_links_0268(minecraft_uuid,user_id,minecraft_name)
 VALUES($1,$2,$3) ON CONFLICT(minecraft_uuid) DO UPDATE SET
 minecraft_name=EXCLUDED.minecraft_name, verified_at=now(),updated_at=now()
 WHERE official_identity_links_0268.user_id=EXCLUDED.user_id
 RETURNING minecraft_uuid,minecraft_name,verified_at`, uuid, owner, name).
		Scan(&result.MinecraftUUID, &result.MinecraftName, &result.VerifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OfficialNeverLink0268{}, ErrOfficialLinkOwned0268
	}
	return result, err
}

func (r *SQLRepository) RemoveOfficialLink0268(ctx context.Context, owner, uuid string) error {
	if err := r.check(); err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM official_identity_links_0268 WHERE user_id=$1 AND minecraft_uuid=$2`, owner, uuid)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrOfficialLinkAbsent0268
	}
	return nil
}
