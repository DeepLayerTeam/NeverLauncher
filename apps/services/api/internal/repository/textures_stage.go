package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// StageTextureUpload0253 резервирует хеш проверенного в памяти нормализованного PNG
// и учитывает квоту владельца ДО физической записи. Неудачные загрузки отслеживаются
// как staging-объекты и могут быть очищены GC через семь дней. Ревизия выбора
// проверяется заранее; окончательный CAS по-прежнему обязателен при фиксации.
func (r *SQLRepository) StageTextureUpload0253(ctx context.Context, profile model.MinecraftProfile, input VerifiedTexture0252) error {
	if err := r.check(); err != nil {
		return err
	}
	if profile.Realm != "local" || profile.Issuer != "launcher" || profile.UserID == "" {
		return ErrNotFound
	}
	if err := validateTextureSelection0251(input.Kind, input.Model, input.Visibility); err != nil {
		return err
	}
	if input.ExpectedRevision < 0 || input.Size < 1 || input.Size > 4<<20 || input.Width < 64 || input.Height < 32 || input.Width > 1024 || input.Height > 1024 {
		return errors.New("Некорректное значение: «texture staging dimensions»")
	}
	if input.Driver != "local" && input.Driver != "s3" {
		return errors.New("Некорректное значение: «texture staging driver»")
	}
	if len(input.Digest) != 64 {
		return errors.New("Некорректное значение: хеш")
	}
	for _, c := range input.Digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("Некорректное значение: хеш")
		}
	}
	if input.ObjectKey != "texture-blobs/sha256/"+input.Digest[:2]+"/"+input.Digest+".png" {
		return errors.New("Некорректное значение: «ключ объекта промежуточного хранилища»")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(253,hashtext($1))`, profile.UserID); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM minecraft_profiles WHERE uuid=$1 AND user_id=$2)`, profile.UUID, profile.UserID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	var allowedSkin, allowedCape bool
	var maxBytes int64
	var maxBlobs int
	if err = tx.QueryRowContext(ctx, `SELECT texture_permission_allowed_0259('', $1, 'skin'),
 texture_permission_allowed_0259('', $1, 'cape'),
 COALESCE((SELECT max_bytes_per_player FROM texture_project_policies WHERE project_id=''),10485760),
 COALESCE((SELECT max_blobs_per_player FROM texture_project_policies WHERE project_id=''),20)`, profile.UserID).Scan(&allowedSkin, &allowedCape, &maxBytes, &maxBlobs); err != nil {
		return err
	}
	if (input.Kind == "skin" && !allowedSkin) || (input.Kind == "cape" && !allowedCape) {
		return ErrTextureUploadDenied0252
	}
	if input.Size > maxBytes {
		return ErrTextureUploadLimit0252
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM texture_assignments WHERE realm='local-project' AND profile_uuid=$1 AND project_id='' AND kind=$2 FOR UPDATE`, profile.UUID, input.Kind).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		if input.ExpectedRevision != 0 {
			return ErrTextureRevisionConflict0251
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && revision != input.ExpectedRevision {
		return ErrTextureRevisionConflict0251
	}
	var count int
	var used int64
	var owned bool
	if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(b.byte_size),0) FROM texture_blob_owners o JOIN texture_blobs b ON b.digest=o.digest WHERE o.user_id=$1`, profile.UserID).Scan(&count, &used); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM texture_blob_owners WHERE user_id=$1 AND digest=$2)`, profile.UserID, input.Digest).Scan(&owned); err != nil {
		return err
	}
	if !owned && (count >= maxBlobs || used > maxBytes-input.Size) {
		return ErrTextureUploadLimit0252
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_blobs(digest,byte_size,width,height,media_type,storage_driver,object_key,status)
 VALUES($1,$2,$3,$4,'image/png',$5,$6,'staging') ON CONFLICT(digest) DO NOTHING`, input.Digest, input.Size, input.Width, input.Height, input.Driver, input.ObjectKey); err != nil {
		return err
	}
	var size int64
	var driver, key, status string
	if err = tx.QueryRowContext(ctx, `SELECT byte_size,storage_driver,object_key,status FROM texture_blobs WHERE digest=$1 FOR UPDATE`, input.Digest).Scan(&size, &driver, &key, &status); err != nil {
		return err
	}
	if size != input.Size || driver != input.Driver || key != input.ObjectKey || (status != "verified" && status != "staging") {
		return fmt.Errorf("Конфликт контрольных сумм при подготовке или идёт сборка мусора")
	}
	// Обновляйте отметку под той же блокировкой строки, что выборщик GC SKIP
	// LOCKED. Ранее осиротевший, но проверенный хеш нельзя удалять, пока другой
	// аутентифицированный пользователь загружает его вновь.
	if _, err = tx.ExecContext(ctx, `UPDATE texture_blobs SET last_upload_at=now() WHERE digest=$1 AND status IN ('verified','staging')`, input.Digest); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO texture_blob_owners(user_id,digest) VALUES($1,$2) ON CONFLICT DO NOTHING`, profile.UserID, input.Digest); err != nil {
		return err
	}
	return tx.Commit()
}
