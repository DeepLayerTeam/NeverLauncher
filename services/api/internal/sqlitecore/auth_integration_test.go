package sqlitecore

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func setupAuth(t *testing.T) (*Repository, *Auth, string, string) {
	t.Helper()
	repo, path := openTest(t)
	pass := "tested-password-with-entropy"
	hashed, e := localpassword.Hash(pass)
	if e != nil {
		t.Fatal(e)
	}
	_, e = repo.SaveUser(context.Background(), model.User{ID: "owner", Email: "owner@test", RoleID: "owner", Status: "active", PasswordHash: hashed}, "bootstrap")
	if e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		t.Fatal(e)
	}
	auth, e := repo.Auth(key)
	if e != nil {
		t.Fatal(e)
	}
	return repo, auth, path, pass
}
func TestAuthRotateReplayAndRestart(t *testing.T) {
	r, a, path, pw := setupAuth(t)
	ctx := context.Background()
	t1, e := a.LoginLocal(ctx, "OWNER@test", pw, "", "launcher")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateAccess(ctx, t1.AccessToken); e != nil {
		t.Fatal(e)
	}
	t2, e := a.RotateRefresh(ctx, t1.RefreshToken)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateAccess(ctx, t1.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("старый токен доступа остаётся действительным после ротации: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); e != nil {
		t.Fatal(e)
	}
	if _, e = a.RotateRefresh(ctx, t1.RefreshToken); !errors.Is(e, ErrRefreshReuse) {
		t.Fatalf("повторное использование токена не обнаружено: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("допущен скомпрометированный токен доступа: %v", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	// Новый читатель должен наблюдать устойчивую компрометацию семейства.
	key := a.key[:]
	a, e = r.Auth(key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.RotateRefresh(ctx, t2.RefreshToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("признак компрометации потерян после перезапуска: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("отзыв токена потерян после перезапуска: %v", e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestSQLiteMFAEnrollmentRecoveryAndRevocation(t *testing.T) {
	_, a, _, pw := setupAuth(t)
	ctx := context.Background()
	before, e := a.LoginLocal(ctx, "owner@test", pw, "", "device")
	if e != nil {
		t.Fatal(e)
	}
	secret, e := a.StartTOTP(ctx, "owner", pw)
	if e != nil {
		t.Fatal(e)
	}
	code, e := totpAt(secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	codes, e := a.ConfirmTOTP(ctx, "owner", pw, code)
	if e != nil {
		t.Fatal(e)
	}
	if len(codes) != 8 {
		t.Fatalf("восстановление %d", len(codes))
	}
	if _, e = a.ValidateAccess(ctx, before.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("сессия до прохождения MFA остаётся действительной")
	}
	if _, e = a.LoginLocal(ctx, "owner@test", pw, "", "device"); !errors.Is(e, ErrMFARequired) {
		t.Fatalf("обход многофакторной аутентификации: %v", e)
	}
	token, e := a.LoginLocal(ctx, "owner@test", pw, codes[0], "device")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@test", pw, codes[0], "device"); !errors.Is(e, ErrMFARequired) {
		t.Fatalf("Повторное использование данных восстановления ошибочно разрешено: %v", e)
	}
	n, e := a.RecoveryRemaining(ctx, "owner")
	if e != nil || n != 7 {
		t.Fatalf("Осталось=%d %v", n, e)
	}
	if e = a.DisableTOTP(ctx, "owner", pw, codes[1]); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateAccess(ctx, token.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("сессия сохранилась после отключения MFA")
	}
	if _, e = a.LoginLocal(ctx, "owner@test", pw, "", "device"); e != nil {
		t.Fatalf("вход по паролю сработал после отключения: %v", e)
	}
}
func TestMinecraftIdentityImmutableAndAuthEpoch(t *testing.T) {
	r, a, path, pw := setupAuth(t)
	ctx := context.Background()
	p := model.MinecraftProfile{UserID: "owner", UUID: "123e4567-e89b-42d3-a456-426614174000", Name: "Steve_1", Issuer: "launcher"}
	out, e := a.SaveMinecraftIdentity(ctx, p, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if out.UUID != p.UUID {
		t.Fatal("UUID неожиданно изменился")
	}
	login, e := a.LoginLocal(ctx, "owner@test", pw, "", "launcher")
	if e != nil {
		t.Fatal(e)
	}
	_, minecraft, e := a.IssueMinecraftSession(ctx, login.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, minecraft); e != nil {
		t.Fatal(e)
	}
	p.UUID = "123e4567-e89b-42d3-a456-426614174001"
	if _, e = a.SaveMinecraftIdentity(ctx, p, "owner"); !errors.Is(e, ErrImmutable) {
		t.Fatalf("UUID неожиданно изменился: %v", e)
	}
	// Имитируйте смену пароля или роли в существующем репозитории 0.32.2.
	if e = r.UpdatePassword(ctx, "owner", "new-password-hash", "owner"); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, minecraft); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("токен Minecraft сохранился после смены эпохи: %v", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
	a, e = r.Auth(a.key[:])
	if e != nil {
		t.Fatal(e)
	}
	out, e = a.MinecraftIdentity(ctx, "owner")
	if e != nil || out.UUID != "123e4567-e89b-42d3-a456-426614174000" {
		t.Fatalf("идентичность потеряна: %v %+v", e, out)
	}
}
func TestRefreshConcurrentReplayIsFailClosed(t *testing.T) {
	_, a, _, pw := setupAuth(t)
	ctx := context.Background()
	init, e := a.LoginLocal(ctx, "owner@test", pw, "", "test")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := a.RotateRefresh(ctx, init.RefreshToken); outcomes <- err }()
	}
	wg.Wait()
	close(outcomes)
	succeeded, replayed := 0, 0
	for e := range outcomes {
		switch {
		case e == nil:
			succeeded++
		case errors.Is(e, ErrRefreshReuse):
			replayed++
		default:
			t.Fatal(e)
		}
	}
	if succeeded != 1 || replayed != 1 {
		t.Fatalf("ротация: CAS=%d, повторное использование=%d", succeeded, replayed)
	}
	if _, e = a.ValidateAccess(ctx, init.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("исходный токен доступа остаётся действительным")
	}
}
func TestTOTPReplayAndRFC6238(t *testing.T) {
	// Общий секрет RFC6238 и первое ожидаемое восьмизначное значение 94287082.
	// Шестизначная версия берёт последние шесть десятичных цифр.
	secret := []byte("12345678901234567890")
	if got := totpCode(secret, 59/30); got != "287082" {
		t.Fatalf("Тестовый вектор TOTP: %s", got)
	}
	if step, ok := checkTOTP(secret, "287082", time.Unix(59, 0), -1); !ok || step != 1 {
		t.Fatal("код TOTP отклонён")
	}
	if _, ok := checkTOTP(secret, "287082", time.Unix(59, 0), 1); ok {
		t.Fatal("допущен повторно использованный временной интервал")
	}
}
func TestSQLiteSchemaUpgrade322To323(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	// Имитируйте существующую БД 0.32.2 с сохранением основных данных
	// пользователей и проектов.
	s, e := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	e = s.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, name := range []string{"durable_job_attempts", "durable_jobs", "durable_outbox", "durable_scope_leases", "bridge_join_tickets", "bridge_nonces", "bridge_nodes", "auth_revocation_events", "minecraft_sessions", "minecraft_profiles", "mfa_recovery", "mfa_totp", "access_tokens", "refresh_tokens", "refresh_families", "auth_sessions"} {
			if _, er := q.ExecContext(ctx, "DROP TABLE "+name); er != nil {
				return er
			}
		}
		_, er := q.ExecContext(ctx, "PRAGMA user_version=322")
		return er
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
	counts, e := r.Count(ctx)
	if e != nil || counts["roles"] != 8 {
		t.Fatalf("после обновления потеряно основное состояние: %v %+v", e, counts)
	}
}
func TestNoSQLiteIntegrationOnOverlay(t *testing.T) {
	if os.Getenv("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1" {
		t.Skip("Строгая сертификация файловой системы выполняется только в нативной среде CI")
	}
}

func TestSQLiteWrongMFAKeyAndRecoveryPersistence(t *testing.T) {
	r, a, path, password := setupAuth(t)
	ctx := context.Background()
	secret, e := a.StartTOTP(ctx, "owner", password)
	if e != nil {
		t.Fatal(e)
	}
	code, e := totpAt(secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := a.ConfirmTOTP(ctx, "owner", password, code)
	if e != nil {
		t.Fatal(e)
	}
	// Секрет НЕ должен сохраняться в открытом виде.
	e = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var ciphertext []byte
		if er := q.QueryRowContext(ctx, `SELECT secret_ciphertext FROM mfa_totp WHERE user_id='owner'`).Scan(&ciphertext); er != nil {
			return er
		}
		if strings.Contains(string(ciphertext), secret) {
			return errors.New("TOTP plaintext found in database")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	wrong := make([]byte, 32)
	if _, e = rand.Read(wrong); e != nil {
		t.Fatal(e)
	}
	alt, e := r.Auth(wrong)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = alt.LoginLocal(ctx, "owner@test", password, "123456", "desktop"); !errors.Is(e, ErrMFARequired) && !errors.Is(e, ErrAuthentication) {
		t.Fatalf("принят неверный ключ: %v", e)
	}
	a, e = r.Auth(a.key[:])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@test", password, recovery[0], "desktop"); e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@test", password, recovery[0], "desktop"); !errors.Is(e, ErrMFARequired) {
		t.Fatal("после перезапуска допущено повторное использование кода восстановления")
	}
}
func TestMinecraftCascadeRevokeUserAndStaleSession(t *testing.T) {
	r, a, _, pw := setupAuth(t)
	ctx := context.Background()
	identity := model.MinecraftProfile{UserID: "owner", UUID: "123e4567-e89b-42d3-a456-426614174000", Name: "Tester_01"}
	if _, e := a.SaveMinecraftIdentity(ctx, identity, "owner"); e != nil {
		t.Fatal(e)
	}
	login, e := a.LoginLocal(ctx, "owner@test", pw, "", "desktop")
	if e != nil {
		t.Fatal(e)
	}
	id, token, e := a.IssueMinecraftSession(ctx, login.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.RevokeMinecraftSession(ctx, "owner", id, "logout-game"); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, token); !errors.Is(e, ErrAuthentication) {
		t.Fatal("выход из учётной записи Minecraft проигнорирован")
	}
	_, token, e = a.IssueMinecraftSession(ctx, login.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	n, e := a.RevokeUserSessions(ctx, "owner", "account-logout")
	if e != nil || n != 1 {
		t.Fatalf("Отзывов: %d; %v", n, e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, token); !errors.Is(e, ErrAuthentication) {
		t.Fatal("токен Minecraft остался действительным после выхода из основной учётной записи")
	}
	if _, e = a.ValidateAccess(ctx, login.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("токен доступа остался действительным после выхода из учётной записи")
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
