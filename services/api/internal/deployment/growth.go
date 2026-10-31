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

// GrowthReport represents actual external dependency checks; it is NOT a
// claim of completed multi-host failover certification.
type GrowthReport struct {
	Mode        Mode      `json:"mode"`
	PostgreSQL  bool      `json:"postgresql"`
	RedisLease  bool      `json:"redisLease"`
	S3RoundTrip bool      `json:"s3RoundTrip"`
	CheckedAt   time.Time `json:"checkedAt"`
}

// VerifyGrowth checks the real infrastructure BEFORE migrations, workers and
// listeners start. It never falls back to local storage, memory or SQLite.
// A second live Redis client and a second S3 client must see the same writes.
func VerifyGrowth(ctx context.Context, cfg config.Config, plan Plan) (GrowthReport, error) {
	r := GrowthReport{Mode: plan.Mode}
	if plan.Mode != NetworkHA && plan.Mode != Standard {
		return r, nil
	}
	if err := verifyPostgresGrowth(ctx, cfg.DatabaseDSN); err != nil {
		return r, fmt.Errorf("PostgreSQL transactional fencing: %w", err)
	}
	r.PostgreSQL = true
	if plan.Mode == NetworkHA {
		if err := verifyRedisGrowth(ctx, cfg.RedisURL); err != nil {
			return r, fmt.Errorf("Redis distributed lease fencing: %w", err)
		}
		r.RedisLease = true
	}
	if plan.Storage == "s3" || plan.Storage == "s3-compatible" {
		s3 := storage.S3Config{Endpoint: cfg.StorageS3Endpoint, PublicURL: cfg.StorageS3PublicURL,
			Bucket: cfg.StorageS3Bucket, Region: cfg.StorageS3Region, AccessKey: cfg.StorageS3AccessKey,
			SecretKey: cfg.StorageS3SecretKey, PathStyle: cfg.StorageS3PathStyle}
		if err := verifyS3Growth(ctx, s3); err != nil {
			return r, fmt.Errorf("S3 cross-client read/write/delete: %w", err)
		}
		r.S3RoundTrip = true
	} else if plan.Mode == NetworkHA {
		return r, errors.New("Network/HA requires tested shared S3")
	}
	r.CheckedAt = time.Now().UTC()
	return r, nil
}

// Two separately pinned PostgreSQL sessions confirm that transaction-scoped
// advisory fencing is shared, and that a released fence can be reclaimed.
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
		return errors.New("empty PostgreSQL database identity")
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
		return errors.New("could not acquire first advisory transaction lock")
	}
	var concurrent bool
	if err := b.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&concurrent); err != nil {
		return err
	}
	if concurrent {
		return errors.New("independent PostgreSQL session bypassed advisory lock")
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := b.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&concurrent); err != nil {
		return err
	}
	if !concurrent {
		return errors.New("PostgreSQL fencing lock did not release on transaction commit")
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
		return fmt.Errorf("first Redis lease acquisition: acquired=%t error=%w", acquired, err)
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.ReleaseCommandLease(cleanCtx, serverID, commandID, ownerA, tokenA)
		_ = b.ReleaseCommandLease(cleanCtx, serverID, commandID, ownerB, tokenB)
	}()
	acquired, err = b.AcquireCommandLease(ctx, serverID, commandID, ownerB, tokenB, 15*time.Second)
	if err != nil || acquired {
		return fmt.Errorf("second Redis client bypassed lease: acquired=%t error=%w", acquired, err)
	}
	if err = b.ReleaseCommandLease(ctx, serverID, commandID, ownerB, tokenB); err != nil {
		return err
	}
	valid, err := a.VerifyCommandLease(ctx, serverID, commandID, ownerA, tokenA)
	if err != nil || !valid {
		return fmt.Errorf("non-owner removed lease: %v / %w", valid, err)
	}
	if err = a.ReleaseCommandLease(ctx, serverID, commandID, ownerA, tokenA); err != nil {
		return err
	}
	acquired, err = b.AcquireCommandLease(ctx, serverID, commandID, ownerB, tokenB, 15*time.Second)
	if err != nil || !acquired {
		return fmt.Errorf("lease takeover after release: acquired=%t error=%w", acquired, err)
	}
	if err = a.ReleaseCommandLease(ctx, serverID, commandID, ownerA, tokenA); err != nil {
		return err
	}
	valid, err = b.VerifyCommandLease(ctx, serverID, commandID, ownerB, tokenB)
	if err != nil || !valid {
		return fmt.Errorf("stale owner removed new lease: %v / %w", valid, err)
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
			err = errors.Join(err, fmt.Errorf("remove S3 probe object: %w", removeErr))
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
		return errors.New("cross-client S3 content or checksum mismatch")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = writer.Delete(ctx, projectID, versionID, path); err != nil {
		return fmt.Errorf("delete S3 probe: %w", err)
	}
	afterDelete, _, readErr := reader.OpenContext(ctx, projectID, versionID, path)
	if afterDelete != nil {
		_ = afterDelete.Close()
		return errors.New("S3 deleted probe remains readable")
	}
	if !errors.Is(readErr, storage.ErrObjectNotFound) {
		return fmt.Errorf("S3 deleted probe did not return 404: %w", readErr)
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
