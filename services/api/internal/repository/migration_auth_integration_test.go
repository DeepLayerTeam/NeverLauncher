//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcredentials"
	gi "gitflic.ru/skif4er/launcher/services/api/internal/gravitidentity"
	mw "gitflic.ru/skif4er/launcher/services/api/internal/migrationworkflow"
)

// Нужна одноразовая PostgreSQL. Проверяются настоящие вставки, откат транзакции,
// повтор квитанции, владение UUID и повтор с паролем, обновлённым CAS.
func TestMigrationAuthAtomicIdempotent0335(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("Требуется временный экземпляр PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	repo := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer repo.db.Close()
	if _, e := repo.ApplyMigrations(ctx); e != nil {
		t.Fatal(e)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := "auth335-" + suffix
	if _, e := repo.db.ExecContext(ctx, `INSERT INTO projects(id,name) VALUES($1,$1)`, project); e != nil {
		t.Fatal(e)
	}
	var userID, secondUserID string
	defer func() {
		c := context.Background()
		idQuery := `SELECT id FROM migration_runs_0331 WHERE project_id=$1`
		for _, table := range []string{"migration_auth_imports_0335", "migration_identity_rows_0334", "migration_identity_snapshots_0334", "migration_source_inventory_0333", "migration_compatibility_0332", "migration_events_0331"} {
			_, _ = repo.db.ExecContext(c, `DELETE FROM `+table+` WHERE run_id IN (`+idQuery+`)`, project)
		}
		_, _ = repo.db.ExecContext(c, `DELETE FROM migration_runs_0331 WHERE project_id=$1`, project)
		if userID != "" {
			_, _ = repo.db.ExecContext(c, `DELETE FROM users WHERE id=$1`, userID)
		}
		if secondUserID != "" {
			_, _ = repo.db.ExecContext(c, `DELETE FROM users WHERE id=$1`, secondUserID)
		}
		_, _ = repo.db.ExecContext(c, `DELETE FROM projects WHERE id=$1`, project)
	}()
	run, e := repo.CreateMigration0331(ctx, project, "gravit", "auth-migration-0335-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run.ID, "worker-0335", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	source := inventoryFixture0333(t, "auth335-source")
	if _, e = repo.SaveMigrationInventory0333(ctx, run.ID, source); e != nil {
		t.Fatal(e)
	}
	account := gi.Account{Provider: "sql", SourceID: "db-id-" + suffix, Username: "Auth335", UUID: "11111111-2222-4333-8444-555555555555", SourcePath: "sql-export/users.csv"}
	mapped, e := repo.SaveMigrationIdentities0334(ctx, run.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{account})
	if e != nil || mapped.Summary["pending_import"] != 1 {
		t.Fatalf("Сопоставление: %+v %v", mapped, e)
	}
	encoded, e := fileauth.EncodeCredential("sha256-hex", strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	c := gc.Credential{Account: account, PasswordHash: encoded, Algorithm: "sha256-hex", State: "importable"}
	input := []gc.Credential{c}
	dry, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, true)
	if e != nil || !dry.DryRun || dry.Imported != 1 {
		t.Fatalf("Пробный запуск: %+v %v", dry, e)
	}
	userID = migratedUserID0335(account)
	var count int
	if e = repo.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id=$1`, userID).Scan(&count); e != nil || count != 0 {
		t.Fatal("Пробная операция создала пользователей", e)
	}
	// Неверный выбор формата хеша отклоняется серверным парсером источника; после
	// импорта решения квитанцию нельзя повторить с другим форматом.
	saved, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, false)
	if e != nil || saved.Imported != 1 || saved.DryRun {
		t.Fatalf("Импорт: %+v %v", saved, e)
	}
	var hash, uuid, role string
	e = repo.db.QueryRowContext(ctx, `SELECT u.password_hash,m.uuid,u.role_id FROM users u JOIN minecraft_profiles m ON m.user_id=u.id WHERE u.id=$1`, userID).Scan(&hash, &uuid, &role)
	if e != nil || hash != encoded || uuid != account.UUID || role != "player" {
		t.Fatalf("Некорректные учётная запись или UUID: %q %q %q %v", hash, uuid, role, e)
	}
	if _, e = repo.db.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, userID, "$argon2id$verified-upgrade"); e != nil {
		t.Fatal(e)
	}
	replay, e := repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "", input, false)
	if e != nil || replay.Imported != 1 {
		t.Fatalf("повторное выполнение: %+v %v", replay, e)
	}
	if _, e = repo.ImportMigrationCredentials0335(ctx, run.ID, source.SourceSHA256, "bcrypt", input, false); !errors.Is(e, mw.ErrConflict) {
		t.Fatalf("Повторно применено изменённое решение: %v", e)
	}
	if e = repo.db.QueryRowContext(ctx, `SELECT count(*) FROM migration_events_0331 WHERE run_id=$1 AND kind='gravit_auth_imported'`, run.ID).Scan(&count); e != nil || count != 1 {
		t.Fatalf("Ожидалось ровно одно событие: %d %v", count, e)
	}

	// Отдельная миграция может сопоставить аккаунт по точному UUID, но не менять
	// его Never-учётные данные, даже если оператор явно предложил другой хеш
	// источника.
	run2, e := repo.CreateMigration0331(ctx, project, "gravit", "auth-second-run-0335-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run2.ID, "worker-2", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run2.ID, source); e != nil {
		t.Fatal(e)
	}
	matched, e := repo.SaveMigrationIdentities0334(ctx, run2.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{account})
	if e != nil || matched.Summary["matched"] != 1 {
		t.Fatalf("Ожидалось совпадение UUID: %+v %v", matched, e)
	}
	replacement := c
	replacement.PasswordHash = strings.Repeat("c", 64)
	preserved, e := repo.ImportMigrationCredentials0335(ctx, run2.ID, source.SourceSHA256, "", []gc.Credential{replacement}, false)
	if e != nil || preserved.ExistingUnchanged != 1 || preserved.Imported != 0 || preserved.Complete {
		t.Fatalf("Сопоставленная учётная запись перезаписана: %+v %v", preserved, e)
	}
	if e = repo.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&hash); e != nil || hash != "$argon2id$verified-upgrade" {
		t.Fatalf("Пароль источника перезаписал пароль Never: %v %q", e, hash)
	}
	// В версии 0.44.4 два независимых SQL-источника Gravit могут использовать
	// id=1. Импорт второго UUID должен создавать отдельную учётную запись Never,
	// а не сталкиваться с локальным первичным ключом первой БД.
	run3, e := repo.CreateMigration0331(ctx, project, "gravit", "auth-third-run-0444-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"target_check", "target_inventory"} {
		lease, e := repo.ClaimMigration0331(ctx, run3.ID, "worker-3", 10*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repo.CheckpointMigration0331(ctx, lease, step, []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = repo.SaveMigrationInventory0333(ctx, run3.ID, source); e != nil {
		t.Fatal(e)
	}
	other := gi.Account{Provider: "sql", SourceID: account.SourceID, Username: "Auth336", UUID: "22222222-2222-4333-8444-555555555555", SourcePath: "sql-export/users.csv"}
	otherMapping, e := repo.SaveMigrationIdentities0334(ctx, run3.ID, source.SourceSHA256, source.ManifestSHA256, []gi.Account{other})
	if e != nil || otherMapping.Summary["pending_import"] != 1 {
		t.Fatalf("Вторая идентичность SQL: %+v %v", otherMapping, e)
	}
	otherCredential := gc.Credential{Account: other, PasswordHash: encoded, Algorithm: "sha256-hex", State: "importable"}
	otherResult, e := repo.ImportMigrationCredentials0335(ctx, run3.ID, source.SourceSHA256, "", []gc.Credential{otherCredential}, false)
	if e != nil || otherResult.Imported != 1 {
		t.Fatalf("Второй импорт SQL: %+v %v", otherResult, e)
	}
	secondUserID = migratedUserID0335(other)
	if secondUserID == userID {
		t.Fatal("Другой UUID импортирован первому пользователю SQL")
	}
	var otherUUID string
	if e = repo.db.QueryRowContext(ctx, `SELECT uuid FROM minecraft_profiles WHERE user_id=$1`, secondUserID).Scan(&otherUUID); e != nil || otherUUID != other.UUID {
		t.Fatalf("Второй UUID потерян: %s %v", otherUUID, e)
	}

}
