package sqlitepg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"github.com/jackc/pgx/v5"
)

func TestTypesAndDigest(t *testing.T) {
	types := map[string]string{"INTEGER": "BIGINT", "TEXT": "TEXT", "VARCHAR(20)": "TEXT", "BLOB": "BYTEA", "DOUBLE": "DOUBLE PRECISION"}
	for input, expect := range types {
		actual, err := columnType(input)
		if err != nil || actual != expect {
			t.Fatalf("%q -> %q, %v", input, actual, err)
		}
	}
	if _, err := columnType("NUMERIC"); err == nil {
		t.Fatal("значение с типом NUMERIC нельзя округлять без предупреждения")
	}
	if _, err := identifier(""); err == nil {
		t.Fatal("Пустой идентификатор ошибочно принят")
	}
	if v, _ := identifier(`a"b`); v != `"a""b"` {
		t.Fatalf("некорректное экранирование идентификатора: %s", v)
	}
	s, b, err := rowDigest([]any{"abc", []byte{0, 1, 2}, int64(12), nil})
	if err != nil || len(b) != sha256.Size || len(s) != 64 {
		t.Fatal(s, err)
	}
	if _, _, err = rowDigest([]any{make(chan int)}); err == nil {
		t.Fatal("Неподдерживаемые значения ошибочно приняты")
	}
	pk := tableInfo{Name: "test", Columns: []column{{Name: "id", Type: "TEXT", PK: 1}, {Name: "value", Type: "BLOB"}}}
	ddl, err := sqlCreate(pk)
	if err != nil || !strings.Contains(ddl, `PRIMARY KEY ("id")`) || !strings.Contains(ddl, `"value" BYTEA`) {
		t.Fatalf("DDL: %s %v", ddl, err)
	}
}
func TestMissingCoreStateFailsClosed(t *testing.T) {
	if err := requireCoreTables([]tableInfo{{Name: "projects"}}); err == nil {
		t.Fatal("допущено отсутствие долговременного состояния")
	}
}

// Требуется действующая служба PostgreSQL и локальный том ext4/XFS/Btrfs.
// LAUNCHER_PG_TEST_DSN должна указывать изолированную тестовую БД.
func TestPGStagingMigration(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL test DB not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var preexisting bool
	if err = pg.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)", Schema).Scan(&preexisting); err != nil {
		t.Fatal(err)
	}
	if preexisting {
		t.Fatal("тестовая база уже содержит схему переноса SQLite; разрушительный сброс запрещён")
	}
	pg.Close(ctx)
	t.Cleanup(func() {
		p, e := pgx.Connect(context.Background(), dsn)
		if e == nil {
			_, _ = p.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+quoted(Schema)+" CASCADE")
			_ = p.Close(context.Background())
		}
	})
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	backup := filepath.Join(dir, "backup.db")
	repo, err := sqlitecore.Open(ctx, sqlitedurable.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("Хост SQLite должен поддерживать WAL: %v", err)
	}
	project, err := repo.SaveProject(ctx, model.Project{ID: "sample", Name: "Sample"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	_ = project
	user, err := repo.SaveUser(ctx, model.User{ID: "user-1", Email: "owner@example.test", DisplayName: "Owner", RoleID: "owner", Status: "active", PasswordHash: "hash"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	hash := strings.Repeat("a", 64)
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	packageBytes := []byte{0, 1, 2, 255, 254, 0, 42}
	packageHash := sha256.Sum256(packageBytes)
	updates := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, []any{user.ID, uuid, "Player42", "official", "realm", "subject", "v1", now, now}},
		{`INSERT INTO auth_sessions(id,user_id,auth_epoch,device_id,status,auth_methods,created_at,last_seen_at,expires_at,revoked_at,revoked_reason) VALUES(?,?,1,'device-1','revoked','["password"]',?,?,?,?,?)`, []any{"session-1", user.ID, now, now, now + 1e12, now, "security"}},
		{`INSERT INTO refresh_families(id,session_id,status,created_at,revoked_at) VALUES(?,?,'revoked',?,?)`, []any{"family-1", "session-1", now, now}},
		{`INSERT INTO refresh_tokens(token_hash,family_id,status,created_at,expires_at,consumed_at) VALUES(?,?,'revoked',?,?,?)`, []any{hash, "family-1", now, now + 1e12, now}},
		{`INSERT INTO access_tokens(token_hash,session_id,issued_at,expires_at,revoked_at) VALUES(?,?,?,?,?)`, []any{strings.Repeat("b", 64), "session-1", now, now + 1e12, now}},
		{`INSERT INTO minecraft_sessions(id,user_id,session_id,profile_uuid,access_hash,status,created_at,expires_at,revoked_at,revoked_reason) VALUES(?,?,?,?,?,'revoked',?,?,?,?)`, []any{"mc-1", user.ID, "session-1", uuid, strings.Repeat("c", 64), now, now + 1e12, now, "security"}},
		{`INSERT INTO durable_scope_leases(scope_key,owner,lease_token,fencing_token,expires_at,updated_at) VALUES(?,?,?,?,?,?)`, []any{"scope-1", "worker-1", "", 42, now, now}},
		{`INSERT INTO package_blobs(digest,data,size_bytes,created_at) VALUES(?,?,?,?)`, []any{hex.EncodeToString(packageHash[:]), packageBytes, len(packageBytes), now}},
		{`INSERT INTO mfa_totp(user_id,status,secret_ciphertext,last_step,created_at,updated_at) VALUES(?,'pending',?,-1,?,?)`, []any{user.ID, []byte{0, 0, 254, 12, 7}, now, now}},
	}
	for _, u := range updates {
		if _, err = db.ExecContext(ctx, u.query, u.args...); err != nil {
			db.Close()
			t.Fatalf("тестовый набор %s: %v", u.query, err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = sqlitedurable.OnlineBackup(ctx, dbPath, backup); err != nil {
		t.Fatal(err)
	}
	result, err := Import(ctx, backup, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReadyForBackendCutover || result.TotalRows < 5 || len(result.Tables) < 25 {
		t.Fatalf("Неожиданный отчёт: %+v", result)
	}
	if result.PostgreSQLSchema != Schema {
		t.Fatal("Неверная целевая схема")
	}
	p, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(ctx)
	var gotUUID string
	if err = p.QueryRow(ctx, "SELECT uuid FROM "+qualified("minecraft_profiles")+" WHERE user_id=$1", user.ID).Scan(&gotUUID); err != nil || gotUUID != uuid {
		t.Fatalf("UUID Minecraft неожиданно изменился: %s %v", gotUUID, err)
	}
	var tokenStatus string
	if err = p.QueryRow(ctx, "SELECT status FROM "+qualified("refresh_tokens")+" WHERE token_hash=$1", hash).Scan(&tokenStatus); err != nil || tokenStatus != "revoked" {
		t.Fatalf("Данные об отзыве потеряны: %s %v", tokenStatus, err)
	}
	var fence int64
	if err = p.QueryRow(ctx, "SELECT fencing_token FROM "+qualified("durable_scope_leases")+" WHERE scope_key='scope-1'").Scan(&fence); err != nil || fence != 42 {
		t.Fatalf("потеряна защита от устаревшего владельца: %d %v", fence, err)
	}
	var packageRead []byte
	if err = p.QueryRow(ctx, "SELECT data FROM "+qualified("package_blobs")+" WHERE digest=$1", hex.EncodeToString(packageHash[:])).Scan(&packageRead); err != nil || !bytes.Equal(packageRead, packageBytes) {
		t.Fatalf("Содержимое пакета неожиданно изменилось: %x %v", packageRead, err)
	}
	var mfaCipher []byte
	if err = p.QueryRow(ctx, "SELECT secret_ciphertext FROM "+qualified("mfa_totp")+" WHERE user_id=$1", user.ID).Scan(&mfaCipher); err != nil || !bytes.Equal(mfaCipher, []byte{0, 0, 254, 12, 7}) {
		t.Fatalf("шифротекст MFA изменился: %x %v", mfaCipher, err)
	}
	var epoch int64
	if err = p.QueryRow(ctx, "SELECT auth_epoch FROM "+qualified("users")+" WHERE id=$1", user.ID).Scan(&epoch); err != nil || epoch != 1 {
		t.Fatalf("Эпоха аутентификации неожиданно изменилась: %d %v", epoch, err)
	}
	var receipt string
	if err = p.QueryRow(ctx, "SELECT id FROM "+qualified("migration_receipt")).Scan(&receipt); err != nil || receipt != result.SnapshotSHA256 {
		t.Fatalf("Несовпадение квитанции: %v", err)
	}
	if _, err = p.Exec(ctx, "DELETE FROM "+qualified("refresh_tokens")+" WHERE token_hash=$1", hash); err == nil {
		t.Fatal("импорт в неизменяемую PostgreSQL позволил удалить отзыв прав")
	}
	if _, err = p.Exec(ctx, "TRUNCATE "+qualified("refresh_tokens")); err == nil {
		t.Fatal("импорт в неизменяемую PostgreSQL допустил TRUNCATE в обход сохранения отзыва прав")
	}
	// Полный физический обратный перенос, а не просто копия манифеста, должен
	// восстановить все байты SQLite, объекты схемы и пользовательские данные.
	exported := filepath.Join(dir, "exported.db")
	reverse, err := Export(ctx, dsn, exported)
	if err != nil {
		t.Fatal(err)
	}
	if reverse.ReadyForBackendCutover || reverse.SnapshotSHA256 != result.SnapshotSHA256 || reverse.TotalRows != result.TotalRows {
		t.Fatalf("квитанция обратного переноса отличается: %+v", reverse)
	}
	exportedManifest, err := sqlitedurable.VerifyBackup(ctx, exported)
	if err != nil || exportedManifest.SHA256 != result.SnapshotSHA256 {
		t.Fatalf("экспортированная SQLite некорректна: %+v %v", exportedManifest, err)
	}
	originalBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	exportedBytes, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, exportedBytes) {
		t.Fatal("байты резервной копии при переносе PostgreSQL -> SQLite не совпадают")
	}
	if _, err = Export(ctx, dsn, exported); err == nil {
		t.Fatal("обратная миграция перезаписала существующую резервную копию")
	}
	// Настоящие операции SQLite Core продолжают работать после обратного импорта.
	restored := filepath.Join(dir, "restored.db")
	if _, err = sqlitedurable.RestoreBackup(ctx, exported, restored, false); err != nil {
		t.Fatal(err)
	}
	opened, err := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: restored})
	if err != nil {
		t.Fatal(err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Import(ctx, backup, dsn); err == nil {
		t.Fatal("повторный запуск перезаписал существующий импорт")
	}
	// Подмена файла нарушает проверяемый по хешу sidecar и блокирует перенос.
	f, err := os.OpenFile(backup, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("X"), 200); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = sqlitedurable.VerifyBackup(ctx, backup); err == nil {
		t.Fatal("Изменённая резервная копия ошибочно принята")
	}
}

func TestReverseTransferMissingReceiptFailsClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := Export(ctx, "", filepath.Join(t.TempDir(), "db.sqlite")); err == nil {
		t.Fatal("Пустая строка подключения PostgreSQL ошибочно принята")
	}
	if _, err := Export(ctx, "nonempty", ""); err == nil {
		t.Fatal("принято пустое место назначения")
	}
}
