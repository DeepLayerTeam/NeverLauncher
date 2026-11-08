package deployment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/serverbridgeha"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

// GrowthReport отражает фактические проверки внешних зависимостей, но НЕ
// удостоверяет завершённую сертификацию многохостового переключения после
// отказа.
type GrowthReport struct {
	Mode        Mode      `json:"mode"`
	PostgreSQL  bool      `json:"postgresql"`
	RedisLease  bool      `json:"redisLease"`
	S3RoundTrip bool      `json:"s3RoundTrip"`
	CheckedAt   time.Time `json:"checkedAt"`
}

// VerifyGrowth проверяет реальную инфраструктуру ДО запуска миграций, рабочих
// процессов и слушателей. Он никогда не переходит на локальное хранилище, память
// или SQLite. Второй живой клиент Redis и второй клиент S3 должны видеть те же
// записи.
func VerifyGrowth(ctx context.Context, cfg config.Config, plan Plan) (GrowthReport, error) {
	r := GrowthReport{Mode: plan.Mode}
	if plan.Mode != NetworkHA && plan.Mode != Standard {
		return r, nil
	}
	if err := verifyPostgresGrowth(ctx, cfg.DatabaseDSN); err != nil {
		return r, fmt.Errorf("Транзакционная блокировка PostgreSQL: %w", err)
	}
	r.PostgreSQL = true
	if plan.Mode == NetworkHA {
		if err := verifyRedisGrowth(ctx, cfg.RedisURL); err != nil {
			return r, fmt.Errorf("Распределённая блокировка аренды Redis: %w", err)
		}
		r.RedisLease = true
	}
	if plan.Storage == "s3" || plan.Storage == "s3-compatible" {
		s3 := storage.S3Config{Endpoint: cfg.StorageS3Endpoint, PublicURL: cfg.StorageS3PublicURL,
			Bucket: cfg.StorageS3Bucket, Region: cfg.StorageS3Region, AccessKey: cfg.StorageS3AccessKey,
			SecretKey: cfg.StorageS3SecretKey, PathStyle: cfg.StorageS3PathStyle}
		if err := verifyS3Growth(ctx, s3); err != nil {
			return r, fmt.Errorf("Проверка чтения, записи и удаления S3 разными клиентами: %w", err)
		}
		r.S3RoundTrip = true
	} else if plan.Mode == NetworkHA {
		return r, errors.New("Для сетевого отказоустойчивого режима требуется проверенное общее хранилище S3")
	}
	r.CheckedAt = time.Now().UTC()
	return r, nil
}

// Две отдельно закреплённые сессии PostgreSQL подтверждают общность
// консультативной блокировки на время транзакции и возможность повторного
// захвата освобождённой блокировки.
func verifyPostgresGrowth(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	a, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer b.Close()
	var databaseName string
	if err := a.QueryRowContext(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		return err
	}
	if strings.TrimSpace(databaseName) == "" {
		return errors.New("Не удалось определить имя базы данных PostgreSQL")
	}
	key, err := randomFenceKey()
	if err != nil {
		return err
	}
	tx, err := a.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var first bool
	if err := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&first); err != nil {
		return err
	}
	if !first {
		return errors.New("Не удалось получить первую консультативную блокировку транзакции")
	}
	var concurrent bool
	if err := b.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&concurrent); err != nil {
		return err
	}
	if concurrent {
		return errors.New("Независимый сеанс PostgreSQL обошёл консультативную блокировку")
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := b.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&concurrent); err != nil {
		return err
	}
	if !concurrent {
		return errors.New("Блокировка PostgreSQL не снялась при фиксации транзакции")
	}
	return nil
}

func verifyRedisGrowth(ctx context.Context, rawURL string) (err error) {
	a, err := serverbridgeha.NewRedis(rawURL)
	if err != nil {
		return err
	}
	b, err := serverbridgeha.NewRedis(rawURL)
	if err != nil {
		return err
	}
	if err = a.Health(ctx); err != nil {
		return err
	}
	if err = b.Health(ctx); err != nil {
		return err
	}
	nonce, err := randomProbeID()
	if err != nil {
		return err
	}
	serverID, commandID := "growth-probe", nonce
	ownerA, ownerB := "replica-a-"+nonce, "replica-b-"+nonce
	tokenA, tokenB := "fence-a-"+nonce, "fence-b-"+nonce
	acquired, err := a.AcquireCommandLease(ctx, serverID, commandID, ownerA, tokenA, 15*time.Second)
	if err != nil || !acquired {
		return fmt.Errorf("Первая попытка захвата аренды Redis: получена=%t, ошибка=%w", acquired, err)
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.ReleaseCommandLease(cleanCtx, serverID, commandID, ownerA, tokenA)
		_ = b.ReleaseCommandLease(cleanCtx, serverID, commandID, ownerB, tokenB)
	}()
	acquired, err = b.AcquireCommandLease(ctx, serverID, commandID, ownerB, tokenB, 15*time.Second)
	if err != nil || acquired {
		return fmt.Errorf("Второй клиент Redis обошёл аренду: получена=%t, ошибка=%w", acquired, err)
	}
	if err = b.ReleaseCommandLease(ctx, serverID, commandID, ownerB, tokenB); err != nil {
		return err
	}
	valid, err := a.VerifyCommandLease(ctx, serverID, commandID, ownerA, tokenA)
	if err != nil || !valid {
		return fmt.Errorf("Сторонний клиент удалил аренду: %v / %w", valid, err)
	}
	if err = a.ReleaseCommandLease(ctx, serverID, commandID, ownerA, tokenA); err != nil {
		return err
	}
	acquired, err = b.AcquireCommandLease(ctx, serverID, commandID, ownerB, tokenB, 15*time.Second)
	if err != nil || !acquired {
		return fmt.Errorf("Перехват аренды после освобождения: получена=%t, ошибка=%w", acquired, err)
	}
	if err = a.ReleaseCommandLease(ctx, serverID, commandID, ownerA, tokenA); err != nil {
		return err
	}
	valid, err = b.VerifyCommandLease(ctx, serverID, commandID, ownerB, tokenB)
	if err != nil || !valid {
		return fmt.Errorf("Прежний владелец удалил новую аренду: %v / %w", valid, err)
	}
	return nil
}

func verifyS3Growth(ctx context.Context, cfg storage.S3Config) (err error) {
	writer, err := storage.NewS3Storage(cfg)
	if err != nil {
		return err
	}
	reader, err := storage.NewS3Storage(cfg)
	if err != nil {
		return err
	}
	if err = writer.Health(ctx); err != nil {
		return err
	}
	nonce, err := randomProbeID()
	if err != nil {
		return err
	}
	projectID, versionID, path := "launcher-growth-check", nonce, "roundtrip.bin"
	payload := []byte("launcher-growth-v1:" + nonce)
	if _, _, err = writer.SaveContext(ctx, projectID, versionID, path, bytes.NewReader(payload)); err != nil {
		return err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if removeErr := writer.Delete(cleanCtx, projectID, versionID, path); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("Удаление тестового объекта S3: %w", removeErr))
		}
	}()
	stream, _, err := reader.OpenContext(ctx, projectID, versionID, path)
	if err != nil {
		return err
	}
	loaded, readErr := io.ReadAll(io.LimitReader(stream, int64(len(payload)+1)))
	closeErr := stream.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(loaded) != len(payload) || sha256.Sum256(loaded) != sha256.Sum256(payload) {
		return errors.New("Не совпадает содержимое или контрольная сумма S3 между клиентами")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = writer.Delete(ctx, projectID, versionID, path); err != nil {
		return fmt.Errorf("Удаление тестового объекта S3: %w", err)
	}
	afterDelete, _, readErr := reader.OpenContext(ctx, projectID, versionID, path)
	if afterDelete != nil {
		_ = afterDelete.Close()
		return errors.New("Удалённый тестовый объект S3 по-прежнему доступен для чтения")
	}
	if !errors.Is(readErr, storage.ErrObjectNotFound) {
		return fmt.Errorf("Удалённый тестовый объект S3 не вернул HTTP 404: %w", readErr)
	}
	return nil
}

func randomProbeID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func randomFenceKey() (int64, error) {
	id, err := randomProbeID()
	if err != nil {
		return 0, err
	}
	b, err := hex.DecodeString(id[:16])
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, x := range b {
		n = (n << 8) | uint64(x)
	}
	return int64(n & 0x7fffffffffffffff), nil
}
