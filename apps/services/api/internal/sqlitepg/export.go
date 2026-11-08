package sqlitepg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"github.com/jackc/pgx/v5"
)

// Export восстанавливает исходный проверенный снимок SQLite Core 326 из
// схемы импорта PostgreSQL. Назначение всегда НОВОЕ; рабочие данные не
// перезаписываются. Реляционное зеркало PG сравнивается с файлом SQLite
// построчно, включая хеши и ограничения внешних ключей, до публикации.
// Это офлайн-перенос данных, а НЕ автоматическое переключение HTTP Backend.
func Export(ctx context.Context, postgresDSN, target string) (out Report, err error) {
	out = Report{Format: importVersion, PostgreSQLSchema: Schema, ReadyForBackendCutover: false}
	if strings.TrimSpace(postgresDSN) == "" || strings.TrimSpace(target) == "" {
		return out, errors.New("Требуются строка подключения PostgreSQL и путь к целевой резервной копии SQLite")
	}
	dest, err := filepath.Abs(target)
	if err != nil {
		return out, err
	}
	if dest == "/" {
		return out, errors.New("Небезопасное значение: целевая база данных SQLite")
	}
	parent := filepath.Dir(dest)
	if st, e := os.Lstat(parent); e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return out, errors.New("Для целевая база данных SQLite требуется: «в существующем закрытом каталоге с правами 0700»")
	}
	for _, suffix := range []string{"", ".json", "-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(dest + suffix); e == nil {
			return out, fmt.Errorf("Целевой объект уже существует: %s", dest+suffix)
		} else if !os.IsNotExist(e) {
			return out, e
		}
	}
	pg, err := pgx.Connect(ctx, postgresDSN)
	if err != nil {
		return out, fmt.Errorf("Подключение к PostgreSQL (%T; DSN скрыт)", err)
	}
	defer pg.Close(context.Background())
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.Background())
	var receiptID string
	var rawReport, rawManifest []byte
	err = tx.QueryRow(ctx, `SELECT id,report,backup_manifest FROM `+qualified("migration_receipt")).Scan(&receiptID, &rawReport, &rawManifest)
	if err != nil {
		return out, fmt.Errorf("Подтверждение проверенного импорта отсутствует: %w", err)
	}
	if err = json.Unmarshal(rawReport, &out); err != nil {
		return out, err
	}
	var manifest sqlitedurable.BackupManifest
	if err = json.Unmarshal(rawManifest, &manifest); err != nil {
		return out, err
	}
	if out.Format != importVersion || out.SQLiteSchema != sqlitecore.SchemaVersion || out.PostgreSQLSchema != Schema || out.ReadyForBackendCutover || out.SnapshotSHA256 != receiptID || manifest.SHA256 != receiptID || manifest.SchemaVersion != sqlitecore.SchemaVersion || manifest.Bytes <= 0 {
		return out, errors.New("Подтверждение переноса PostgreSQL не поддерживается, неполно или противоречиво")
	}
	// Закрытая временная резервная копия не публикуется, пока оба зеркала PostgreSQL
	// и исходные инварианты SQLite-приложения не пройдут проверку.
	dir, err := os.MkdirTemp(parent, ".launcher-export-*")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		return out, err
	}
	tmp := filepath.Join(dir, "snapshot.db")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return out, err
	}
	copyErr := readChunks(ctx, tx, f, manifest.Bytes, manifest.SHA256)
	if copyErr == nil {
		copyErr = f.Sync()
	}
	copyErr = errors.Join(copyErr, f.Close())
	if copyErr != nil {
		return out, copyErr
	}
	side, err := json.Marshal(manifest)
	if err != nil {
		return out, err
	}
	if err = os.WriteFile(tmp+".json", side, 0600); err != nil {
		return out, err
	}
	actual, err := sqlitedurable.VerifyBackup(ctx, tmp)
	if err != nil {
		return out, fmt.Errorf("Проверка целостности восстановленной резервной копии SQLite: %w", err)
	}
	if actual.SHA256 != out.SnapshotSHA256 {
		return out, errors.New("Несовпадение: «SHA-256 восстановленной базы SQLite»")
	}
	if err = verifyRestoredCore(ctx, tmp); err != nil {
		return out, fmt.Errorf("Проверка обязательных условий восстановленного приложения: %w", err)
	}
	src, err := sql.Open("sqlite", "file:"+tmp+"?mode=ro&_pragma=foreign_keys(1)")
	if err != nil {
		return out, err
	}
	src.SetMaxOpenConns(1)
	defs, err := tables(ctx, src)
	if err == nil {
		err = requireCoreTables(defs)
	}
	if err == nil && len(out.Tables) != len(defs) {
		err = errors.New("Набор таблиц PostgreSQL отличается от исходного снимка SQLite")
	}
	for _, table := range defs {
		if err != nil {
			break
		}
		err = verifyPG(ctx, tx, table, out.Tables)
	}
	err = errors.Join(err, src.Close())
	if err != nil {
		return out, fmt.Errorf("Проверка соответствия таблиц PostgreSQL: %w", err)
	}
	// Создать новую копию SQLite и JSON-метаданные, не уничтожая прежних данных.
	// Жёсткая ссылка атомарна; при ошибке неполная пара удаляется. Проверка
	// потребителей всегда требует оба файла и поэтому закрывает доступ при ошибке.
	publishedDB, publishedSide := false, false
	defer func() {
		if err != nil {
			if publishedSide {
				_ = os.Remove(dest + ".json")
			}
			if publishedDB {
				_ = os.Remove(dest)
			}
		}
	}()
	if err = os.Link(tmp, dest); err != nil {
		return out, err
	}
	publishedDB = true
	if err = os.Link(tmp+".json", dest+".json"); err != nil {
		return out, err
	}
	publishedSide = true
	pd, err := os.Open(parent)
	if err != nil {
		return out, err
	}
	err = errors.Join(pd.Sync(), pd.Close())
	if err != nil {
		return out, err
	}
	_, err = sqlitedurable.VerifyBackup(ctx, dest)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func readChunks(ctx context.Context, tx pgx.Tx, dest io.Writer, expectedSize int64, expectedHash string) error {
	rows, err := tx.Query(ctx, `SELECT ordinal,sha256,payload FROM `+qualified("migration_snapshot_chunks")+` ORDER BY ordinal`)
	if err != nil {
		return err
	}
	var count, size int64
	var digest hash.Hash = sha256.New()
	for rows.Next() {
		var ordinal int64
		var savedHash string
		var data []byte
		if err = rows.Scan(&ordinal, &savedHash, &data); err != nil {
			break
		}
		if ordinal != count || len(data) == 0 || len(data) > snapshotChunkSize {
			err = errors.New("Некорректное значение: «или отсутствует фрагмент снимка PostgreSQL»")
			break
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != savedHash {
			err = errors.New("Несовпадение: «SHA-256 фрагмента снимка»")
			break
		}
		n, writeErr := dest.Write(data)
		if writeErr != nil {
			err = writeErr
			break
		}
		if n != len(data) {
			err = io.ErrShortWrite
			break
		}
		_, _ = digest.Write(data)
		count++
		size += int64(len(data))
		if size > expectedSize {
			err = errors.New("Размер снимка превышает значение в манифесте")
			break
		}
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	if count == 0 || size != expectedSize || hex.EncodeToString(digest.Sum(nil)) != expectedHash {
		return errors.New("Несовпадение: «длина или SHA-сумма снимка PostgreSQL»")
	}
	return nil
}
