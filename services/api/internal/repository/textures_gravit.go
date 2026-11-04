package repository

import (
	"context"
	"database/sql"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// GravitImportState02510 не выполняет импорт по предполагаемой идентичности пользователя.
// Она позволяет оператору отличить существовавший ранее выбор от ранее
// завершённого импорта до расходования ресурсов, тогда как UploadTexture0252 обеспечивает
// эти ограничения повторно внутри своей транзакции.
func (r *SQLRepository) GravitImportState02510(ctx context.Context, sourceID, rowID string, p model.MinecraftProfile, kind string) (already bool, revision int64, exists bool, err error) {
	if err = r.check(); err != nil {
		return
	}
	if p.Realm != "local" || p.Issuer != "launcher" || p.UserID == "" {
		err = ErrNotFound
		return
	}
	var verified bool
	err = r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2 AND realm='local' AND issuer='launcher')`, p.UUID, p.UserID).Scan(&verified)
	if err != nil || !verified {
		if err == nil {
			err = ErrNotFound
		}
		return
	}
	err = r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_gravit_import_receipts WHERE source_id=$1 AND external_row_id=$2)`, sourceID, rowID).Scan(&already)
	if err != nil || already {
		return
	}
	err = r.db.QueryRowContext(ctx, `SELECT revision FROM texture_assignments WHERE realm='local-project' AND profile_uuid=$1 AND project_id='' AND kind=$2`, p.UUID, kind).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
		return
	}
	if err == nil {
		exists = true
	}
	return
}
