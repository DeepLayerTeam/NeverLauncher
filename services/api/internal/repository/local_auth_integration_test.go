//go:build !launcher_nopgx

package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
)

// Одноразовая БД PostgreSQL доказывает атомарность импорта, живой поиск
// идентичностей, неизменяемость игрового UUID, откат и CAS без mock SQL.
func TestFileAuthImportPostgres0295(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("требуется одноразовая база в LAUNCHER_TEST_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	r := NewSQLRepository("pgx", dsn, "").(*SQLRepository)
	defer r.db.Close()
	if _, err := r.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("%012x", uint64(time.Now().UnixNano())&0xffffffffffff)
	uuid := "8af62031-2333-4333-8333-" + id
	name := "U" + id[:10]
	sum := sha256.Sum256([]byte("Password-0295-Correct"))
	hash, err := fileauth.EncodeCredential("sha256-hex", hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	account := fileauth.Account{UUID: uuid, Username: name, Email: name + "@fileauth.invalid", PasswordHash: hash}
	// UsernameEmail нормализует регистр. Фикстура использует только суффикс hex в нижнем
	// регистре.
	account.Email, _ = fileauth.UsernameEmail(name)
	key := "gravit-fileauth-" + "8af62031233343338333" + id
	defer r.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, key)
	if count, err := r.ImportFileAuth0295(ctx, []fileauth.Account{account}, true); err != nil || count != 1 {
		t.Fatalf("dry-run: count=%d err=%v", count, err)
	}
	if _, err := r.GetUser(key); err == nil {
		t.Fatal("Пробный запуск сохранил учётные записи")
	}
	if _, err := r.ImportFileAuth0295(ctx, []fileauth.Account{account}, false); err != nil {
		t.Fatal(err)
	}
	user, err := r.GetUser(key)
	if err != nil || user.Email != account.Email || user.RoleID != "player" || user.PasswordHash != hash {
		t.Fatalf("Сохранённый пользователь: %+v %v", user, err)
	}
	identity, err := r.GetAuthIdentityByIssuer("local", "launcher", key)
	if err != nil || identity.UserID != key {
		t.Fatalf("Отсутствует настоящая локальная личность: %+v %v", identity, err)
	}
	profile, err := r.GetMinecraftProfileByUser(key)
	if err != nil || profile.UUID != uuid || profile.Name != name {
		t.Fatalf("UUID Minecraft потерян: %+v %v", profile, err)
	}
	// Вторая коллизия отменяет всю партию. Ранее созданный аккаунт остаётся
	// неизменным.
	other := fileauth.Account{UUID: "8af62031-2333-4333-8333-000000000099", Username: "Unused0099", Email: "unused0099@fileauth.invalid", PasswordHash: hash}
	if _, err := r.ImportFileAuth0295(ctx, []fileauth.Account{other, account}, false); err == nil {
		t.Fatal("Повторный импорт неожиданно принят")
	}
	if _, err := r.GetUser("gravit-fileauth-8af62031233343338333000000000099"); err == nil {
		t.Fatal("После конфликта частично сохранились изменения")
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, "wrong", "$argon2id$v=19$dummy"); err != nil || ok {
		t.Fatalf("CAS проигнорировал ожидаемый хеш: %v %v", ok, err)
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, hash, "$argon2id$v=19$dummy"); err != nil || !ok {
		t.Fatalf("Обновление пароля с CAS: %v %v", ok, err)
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, hash, "$argon2id$v=19$dummy2"); err != nil || ok {
		t.Fatalf("Устаревшие учётные данные перезаписали обновлённый пароль: %v %v", ok, err)
	}
}
