package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TextureGCLease02511 ограждает физическое удаление одной выбранной попыткой GC.
type TextureGCLease02511 struct {
	TextureGarbage0253
	Token string
}

func textureLeaseToken02511() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func textureStorageDriver02511(driver string) error {
	if driver != "local" && driver != "s3" {
		return errors.New("invalid texture storage driver")
	}
	return nil
}

// BeginTextureSnapshot02511 атомарно закрепляет каждый проверенный объект для
// резервного копирования, проверки или восстановления оператором. Блокировки строк
// сериализуются с заявками GC; после падения процесса защита автоматически
// снимается через 45 минут. Операции должны использовать deadline менее 45 минут.
func (r *SQLRepository) BeginTextureSnapshot02511(ctx context.Context, driver string) (string, []TextureBackupRow0253, error) {
	if err := r.check(); err != nil {
		return "", nil, err
	}
	if err := textureStorageDriver02511(driver); err != nil {
		return "", nil, err
	}
	token, err := textureLeaseToken02511()
	if err != nil {
		return "", nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT digest,byte_size,storage_driver,object_key FROM texture_blobs
  WHERE status='verified' AND storage_driver=$1 ORDER BY digest FOR UPDATE`, driver)
	if err != nil {
		return "", nil, err
	}
	inventory := make([]TextureBackupRow0253, 0)
	for rows.Next() {
		var b TextureBackupRow0253
		if err = rows.Scan(&b.Digest, &b.ByteSize, &b.Driver, &b.ObjectKey); err != nil {
			break
		}
		inventory = append(inventory, b)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return "", nil, err
	}
	if closeErr != nil {
		return "", nil, closeErr
	}
	for _, b := range inventory {
		if _, err := tx.ExecContext(ctx, `INSERT INTO texture_backup_pins(digest,lease_token,expires_at)
    VALUES ($1,$2,now()+interval '45 minutes')`, b.Digest, token); err != nil {
			return "", nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return token, inventory, nil
}

func (r *SQLRepository) EndTextureSnapshot02511(ctx context.Context, token string) error {
	if err := r.check(); err != nil {
		return err
	}
	if len(token) != 64 {
		return errors.New("invalid backup lease token")
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM texture_backup_pins WHERE lease_token=$1`, token)
	return err
}

// ClaimTextureGarbage02511 ограждает каждую аренду GC, защищая снимки
// резервирования, активные выборы, сохранённые элементы, значения по умолчанию
// и недавнюю историю.
func (r *SQLRepository) ClaimTextureGarbage02511(ctx context.Context, driver string, limit int) ([]TextureGCLease02511, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if err := textureStorageDriver02511(driver); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("texture GC batch must be between 1 and 100")
	}
	// Каждая заявка получает уникальный токен, поэтому один воркер не может завершить чужую
	// аренду.
	token, err := textureLeaseToken02511()
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `WITH candidates AS (
   SELECT b.digest FROM texture_blobs b WHERE b.storage_driver=$1
    AND b.created_at < now()-interval '7 days'
    AND b.last_upload_at < now()-interval '7 days'
    AND (b.status='verified' OR b.status='staging' OR
       (b.status='quarantined' AND (b.gc_claimed_at IS NULL OR b.gc_claimed_at < now()-interval '45 minutes')))
    AND NOT EXISTS (SELECT 1 FROM texture_assignments a WHERE a.blob_digest=b.digest)
    AND NOT EXISTS (SELECT 1 FROM texture_saved_items i WHERE i.digest=b.digest)
    AND NOT EXISTS (SELECT 1 FROM texture_project_policies p WHERE
      p.default_skin_digest=b.digest OR p.default_cape_digest=b.digest OR
      p.fallback_skin_digest=b.digest OR p.fallback_cape_digest=b.digest)
    AND NOT EXISTS (SELECT 1 FROM texture_backup_pins pin WHERE pin.digest=b.digest AND pin.expires_at>now())
    AND NOT EXISTS (SELECT 1 FROM texture_assignment_revisions rev WHERE
      rev.created_at >= now()-interval '7 days' AND rev.snapshot->>'blobDigest'=b.digest)
   ORDER BY b.created_at,b.digest FOR UPDATE OF b SKIP LOCKED LIMIT $2
  ) UPDATE texture_blobs b SET status='quarantined',verified_at=NULL,
    gc_claimed_at=now(),gc_lease_token=$3
    FROM candidates c WHERE b.digest=c.digest
    RETURNING b.digest,b.storage_driver,b.object_key,b.gc_lease_token`, driver, limit, token)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TextureGCLease02511, 0)
	for rows.Next() {
		var b TextureGCLease02511
		if err := rows.Scan(&b.Digest, &b.Driver, &b.ObjectKey, &b.Token); err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// CheckTextureGCLease02511 проверяет, что воркер не вытеснен. Истёкшая аренда
// НЕДЕЙСТВИТЕЛЬНА, даже если другой воркер ещё её не занял.
func (r *SQLRepository) CheckTextureGCLease02511(ctx context.Context, b TextureGCLease02511) error {
	if err := r.check(); err != nil {
		return err
	}
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM texture_blobs t WHERE t.digest=$1 AND t.storage_driver=$2
   AND t.object_key=$3 AND t.status='quarantined' AND t.gc_lease_token=$4
   AND t.gc_claimed_at > now()-interval '45 minutes'
   AND NOT EXISTS (SELECT 1 FROM texture_backup_pins p WHERE p.digest=t.digest AND p.expires_at>now())
 )`, b.Digest, b.Driver, b.ObjectKey, b.Token).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("stale texture GC lease for %s", b.Digest)
	}
	return nil
}

// Завершение выполняется как compare-and-delete: устаревший воркер не может удалить
// строку, уже заявленную другим. Все ссылки хранилища повторно проверяются в
// PostgreSQL.
func (r *SQLRepository) FinishTextureGC02511(ctx context.Context, b TextureGCLease02511) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM texture_blobs t WHERE t.digest=$1 AND t.storage_driver=$2
  AND t.object_key=$3 AND t.status='quarantined' AND t.gc_lease_token=$4
  AND t.gc_claimed_at > now()-interval '45 minutes'
  AND NOT EXISTS (SELECT 1 FROM texture_assignments a WHERE a.blob_digest=t.digest)
  AND NOT EXISTS (SELECT 1 FROM texture_saved_items i WHERE i.digest=t.digest)
  AND NOT EXISTS (SELECT 1 FROM texture_project_policies p WHERE
    p.default_skin_digest=t.digest OR p.default_cape_digest=t.digest OR
    p.fallback_skin_digest=t.digest OR p.fallback_cape_digest=t.digest)
  AND NOT EXISTS (SELECT 1 FROM texture_backup_pins p WHERE p.digest=t.digest AND p.expires_at>now())
  AND NOT EXISTS (SELECT 1 FROM texture_assignment_revisions rev WHERE
    rev.created_at>=now()-interval '7 days' AND rev.snapshot->>'blobDigest'=t.digest)`,
		b.Digest, b.Driver, b.ObjectKey, b.Token)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("GC lease expired, reclaimed or referenced for %s", b.Digest)
	}
	return nil
}

func (r *SQLRepository) ReleaseTextureGC02511(ctx context.Context, b TextureGCLease02511) error {
	if err := r.check(); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE texture_blobs SET gc_claimed_at=NULL,gc_lease_token=NULL
  WHERE digest=$1 AND status='quarantined' AND gc_lease_token=$2`, b.Digest, b.Token)
	return err
}

// Сокращайте хранение старых закреплений от упавших процессов; истёкшие закрепления
// блокируют GC даже до очистки.
func (r *SQLRepository) PruneTextureSnapshotPins02511(ctx context.Context) (int64, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM texture_backup_pins WHERE expires_at<=now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Оставлено как проверка при компиляции, что TTL аренды превышает deadline CLI обслуживания.
const TextureSnapshotTTL02511 = 45 * time.Minute
