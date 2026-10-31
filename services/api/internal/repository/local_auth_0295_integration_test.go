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

// A disposable PostgreSQL database proves atomic import, live identity lookup,
// immutable game UUID, rollback, and CAS without any mocked SQL database.
func TestFileAuthImportPostgres0295(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable NEVERLAUNCHER_TEST_POSTGRES_DSN")
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
	// `UsernameEmail` normalizes case. This fixture uses only lowercase hex suffix.
	account.Email, _ = fileauth.UsernameEmail(name)
	key := "gravit-fileauth-" + "8af62031233343338333" + id
	defer r.db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, key)
	if count, err := r.ImportFileAuth0295(ctx, []fileauth.Account{account}, true); err != nil || count != 1 {
		t.Fatalf("dry-run: count=%d err=%v", count, err)
	}
	if _, err := r.GetUser(key); err == nil {
		t.Fatal("dry-run committed accounts")
	}
	if _, err := r.ImportFileAuth0295(ctx, []fileauth.Account{account}, false); err != nil {
		t.Fatal(err)
	}
	user, err := r.GetUser(key)
	if err != nil || user.Email != account.Email || user.RoleID != "player" || user.PasswordHash != hash {
		t.Fatalf("persisted user: %+v %v", user, err)
	}
	identity, err := r.GetAuthIdentityByIssuer("local", "launcher", key)
	if err != nil || identity.UserID != key {
		t.Fatalf("missing real local identity: %+v %v", identity, err)
	}
	profile, err := r.GetMinecraftProfileByUser(key)
	if err != nil || profile.UUID != uuid || profile.Name != name {
		t.Fatalf("Minecraft UUID lost: %+v %v", profile, err)
	}
	// Second collision aborts whole batch. Earlier account remains unchanged.
	other := fileauth.Account{UUID: "8af62031-2333-4333-8333-000000000099", Username: "Unused0099", Email: "unused0099@fileauth.invalid", PasswordHash: hash}
	if _, err := r.ImportFileAuth0295(ctx, []fileauth.Account{other, account}, false); err == nil {
		t.Fatal("duplicate import unexpectedly accepted")
	}
	if _, err := r.GetUser("gravit-fileauth-8af62031233343338333000000000099"); err == nil {
		t.Fatal("partial commit after collision")
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, "wrong", "$argon2id$v=19$dummy"); err != nil || ok {
		t.Fatalf("CAS ignored expected hash: %v %v", ok, err)
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, hash, "$argon2id$v=19$dummy"); err != nil || !ok {
		t.Fatalf("CAS password upgrade: %v %v", ok, err)
	}
	if ok, err := r.ReplacePasswordIfMatch0295(ctx, key, hash, "$argon2id$v=19$dummy2"); err != nil || ok {
		t.Fatalf("stale credential rewrote upgraded password: %v %v", ok, err)
	}
}
