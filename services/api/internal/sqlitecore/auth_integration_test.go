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

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func setupAuth(t *testing.T) (*Repository, *Auth, string, string) {
	t.Helper()
	repo, path := openTest(t)
	pass := "tested-password-with-entropy"
	hashed, e := localpassword.Hash(pass)
	if e != nil {
		t.Fatal(e)
	}
	_, e = repo.SaveUser(context.Background(), model.User{ID: "owner", Email: "owner@never.test", RoleID: "owner", Status: "active", PasswordHash: hashed}, "bootstrap")
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
	t1, e := a.LoginLocal(ctx, "OWNER@never.test", pw, "", "launcher")
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
		t.Fatalf("rotated access still valid: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); e != nil {
		t.Fatal(e)
	}
	if _, e = a.RotateRefresh(ctx, t1.RefreshToken); !errors.Is(e, ErrRefreshReuse) {
		t.Fatalf("replay not detected: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("compromised access accepted: %v", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	// A new reader must observe the durable family compromise.
	key := a.key[:]
	a, e = r.Auth(key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.RotateRefresh(ctx, t2.RefreshToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("compromise lost after restart: %v", e)
	}
	if _, e = a.ValidateAccess(ctx, t2.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("revocation lost after restart: %v", e)
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestSQLiteMFAEnrollmentRecoveryAndRevocation(t *testing.T) {
	_, a, _, pw := setupAuth(t)
	ctx := context.Background()
	before, e := a.LoginLocal(ctx, "owner@never.test", pw, "", "device")
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
		t.Fatalf("recovery %d", len(codes))
	}
	if _, e = a.ValidateAccess(ctx, before.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("pre-MFA session valid")
	}
	if _, e = a.LoginLocal(ctx, "owner@never.test", pw, "", "device"); !errors.Is(e, ErrMFARequired) {
		t.Fatalf("MFA bypass: %v", e)
	}
	token, e := a.LoginLocal(ctx, "owner@never.test", pw, codes[0], "device")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@never.test", pw, codes[0], "device"); !errors.Is(e, ErrMFARequired) {
		t.Fatalf("reused recovery accepted: %v", e)
	}
	n, e := a.RecoveryRemaining(ctx, "owner")
	if e != nil || n != 7 {
		t.Fatalf("remaining=%d %v", n, e)
	}
	if e = a.DisableTOTP(ctx, "owner", pw, codes[1]); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateAccess(ctx, token.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("session survived MFA removal")
	}
	if _, e = a.LoginLocal(ctx, "owner@never.test", pw, "", "device"); e != nil {
		t.Fatalf("password login after disable: %v", e)
	}
}
func TestMinecraftIdentityImmutableAndAuthEpoch(t *testing.T) {
	r, a, path, pw := setupAuth(t)
	ctx := context.Background()
	p := model.MinecraftProfile{UserID: "owner", UUID: "123e4567-e89b-42d3-a456-426614174000", Name: "Steve_1", Issuer: "neverlauncher"}
	out, e := a.SaveMinecraftIdentity(ctx, p, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if out.UUID != p.UUID {
		t.Fatal("uuid changed")
	}
	login, e := a.LoginLocal(ctx, "owner@never.test", pw, "", "launcher")
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
		t.Fatalf("uuid changed: %v", e)
	}
	// Simulate a changed password/role from the existing 0.32.2 repository.
	if e = r.UpdatePassword(ctx, "owner", "new-password-hash", "owner"); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, minecraft); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("minecraft survives epoch update: %v", e)
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
		t.Fatalf("identity lost %v %+v", e, out)
	}
}
func TestRefreshConcurrentReplayIsFailClosed(t *testing.T) {
	_, a, _, pw := setupAuth(t)
	ctx := context.Background()
	init, e := a.LoginLocal(ctx, "owner@never.test", pw, "", "test")
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
		t.Fatalf("rotation CAS=%d replay=%d", succeeded, replayed)
	}
	if _, e = a.ValidateAccess(ctx, init.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("original access valid")
	}
}
func TestTOTPReplayAndRFC6238(t *testing.T) {
	// RFC6238 shared secret and first expected 8-digit value 94287082.
	// Our 6-digit version is its last six decimal digits.
	secret := []byte("12345678901234567890")
	if got := totpCode(secret, 59/30); got != "287082" {
		t.Fatalf("TOTP vector: %s", got)
	}
	if step, ok := checkTOTP(secret, "287082", time.Unix(59, 0), -1); !ok || step != 1 {
		t.Fatal("totp rejected")
	}
	if _, ok := checkTOTP(secret, "287082", time.Unix(59, 0), 1); ok {
		t.Fatal("replayed timestep")
	}
}
func TestSQLiteSchemaUpgrade322To323(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	// Simulate an existing 0.32.2 DB, preserving the core user/project data.
	s, e := sqlitedurable.Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	e = s.Write(ctx, func(q sqlitedurable.Executor) error {
		for _, name := range []string{"auth_revocation_events", "minecraft_sessions", "minecraft_profiles", "mfa_recovery", "mfa_totp", "access_tokens", "refresh_tokens", "refresh_families", "auth_sessions"} {
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
		t.Fatalf("upgrade lost core: %v %+v", e, counts)
	}
}
func TestNoSQLiteIntegrationOnOverlay(t *testing.T) {
	if os.Getenv("NEVERLAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1" {
		t.Skip("only run strict filesystem certification in native CI")
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
	// Secret must never be persisted in cleartext.
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
	if _, e = alt.LoginLocal(ctx, "owner@never.test", password, "123456", "desktop"); !errors.Is(e, ErrMFARequired) && !errors.Is(e, ErrAuthentication) {
		t.Fatalf("wrong key accepted: %v", e)
	}
	a, e = r.Auth(a.key[:])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@never.test", password, recovery[0], "desktop"); e != nil {
		t.Fatal(e)
	}
	if _, e = a.LoginLocal(ctx, "owner@never.test", password, recovery[0], "desktop"); !errors.Is(e, ErrMFARequired) {
		t.Fatal("recovery replay after restart")
	}
}
func TestMinecraftCascadeRevokeUserAndStaleSession(t *testing.T) {
	r, a, _, pw := setupAuth(t)
	ctx := context.Background()
	identity := model.MinecraftProfile{UserID: "owner", UUID: "123e4567-e89b-42d3-a456-426614174000", Name: "Tester_01"}
	if _, e := a.SaveMinecraftIdentity(ctx, identity, "owner"); e != nil {
		t.Fatal(e)
	}
	login, e := a.LoginLocal(ctx, "owner@never.test", pw, "", "desktop")
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
		t.Fatal("MC logout ignored")
	}
	_, token, e = a.IssueMinecraftSession(ctx, login.AccessToken, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	n, e := a.RevokeUserSessions(ctx, "owner", "account-logout")
	if e != nil || n != 1 {
		t.Fatalf("revocations %d: %v", n, e)
	}
	if _, e = a.ValidateMinecraftSession(ctx, token); !errors.Is(e, ErrAuthentication) {
		t.Fatal("MC token survived parent logout")
	}
	if _, e = a.ValidateAccess(ctx, login.AccessToken); !errors.Is(e, ErrAuthentication) {
		t.Fatal("access token survived logout")
	}
	if e = r.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
