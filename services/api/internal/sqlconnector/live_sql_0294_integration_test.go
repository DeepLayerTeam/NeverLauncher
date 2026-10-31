package sqlconnector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

// Run against real database servers by setting the DSNs. CI runs all three.
// No test silently substitutes the fake database driver for a live E2E.
func TestLiveSQLLegacyAuthentication0294(t *testing.T) {
	targets := []struct{ name, driver, env string }{
		{"postgresql", "postgresql", "NEVERLAUNCHER_SQL_TEST_POSTGRES_DSN"},
		{"mysql", "mysql", "NEVERLAUNCHER_SQL_TEST_MYSQL_DSN"},
		{"mariadb", "mariadb", "NEVERLAUNCHER_SQL_TEST_MARIADB_DSN"},
	}
	ran := 0
	for _, target := range targets {
		dsn := os.Getenv(target.env)
		if dsn == "" {
			continue
		}
		ran++
		t.Run(target.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			tls := false // isolated loopback CI instances, never use this in production
			cfg := Config{
				ID: "legacy-test", Driver: target.driver, DSN: dsn, Table: "nl_auth_0294_users",
				Columns:  Columns{ID: "account_id", Username: "login_name", Email: "email_addr", Password: "pass_hash", Status: "account_state", MinecraftUUID: "game_uuid"},
				Password: PasswordConfig{Algorithm: "phpass", AllowLegacyHashes: true}, RequireTLS: &tls,
			}
			rt, err := Normalize(cfg)
			if err != nil {
				t.Fatal(err)
			}
			db, err := openDatabase(rt)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS nl_auth_0294_users")
			_, err = db.ExecContext(ctx, `CREATE TABLE nl_auth_0294_users (
                account_id VARCHAR(36) PRIMARY KEY, login_name VARCHAR(64), email_addr VARCHAR(128),
                pass_hash VARCHAR(256) NOT NULL, account_state VARCHAR(20), game_uuid VARCHAR(36)
            )`)
			if err != nil {
				t.Fatal(err)
			}
			defer db.ExecContext(context.Background(), "DROP TABLE IF EXISTS nl_auth_0294_users")
			bind := func(n int) string {
				if target.driver == "postgresql" {
					return fmt.Sprintf("$%d", n)
				}
				return "?"
			}
			ins := "INSERT INTO nl_auth_0294_users (account_id,login_name,email_addr,pass_hash,account_state,game_uuid) VALUES (" +
				strings.Join([]string{bind(1), bind(2), bind(3), bind(4), bind(5), bind(6)}, ",") + ")"
			_, err = db.ExecContext(ctx, ins, "42", "legacy", "legacy@example.test", "$P$B12345678QjY5zqJqT433Q3av7QGRM/", "active", "550e8400-e29b-41d4-a716-446655440000")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("real SQL activation failed: %v", err)
			}
			defer conn.Close()
			auth, err := conn.AuthenticatePassword(ctx, authconnector.PasswordRequest{Identifier: "LEGACY@EXAMPLE.TEST", Secret: "secret"})
			if err != nil || auth.Identity.Subject != "42" || auth.Identity.Claims["minecraftUuid"] != "550e8400-e29b-41d4-a716-446655440000" {
				t.Fatalf("real SQL authentication failed: %+v %v", auth, err)
			}
			if _, err := conn.AuthenticatePassword(ctx, authconnector.PasswordRequest{Identifier: "legacy", Secret: "wrong"}); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
				t.Fatalf("wrong password must fail, got %v", err)
			}
			cfg.Columns.Password = "missing_password_column"
			if rejected, e := New(ctx, cfg); e == nil {
				if rejected != nil {
					rejected.Close()
				}
				t.Fatal("connector activated with nonexistent mapped password column")
			}
			// An unknown stored verifier must not result in local auth fallback.
			_, err = db.ExecContext(ctx, "UPDATE nl_auth_0294_users SET pass_hash="+bind(1)+" WHERE account_id="+bind(2), "unknown", "42")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = conn.AuthenticatePassword(ctx, authconnector.PasswordRequest{Identifier: "legacy", Secret: "secret"}); authconnector.CodeOf(err) != authconnector.ErrMisconfigured {
				t.Fatalf("unknown hash must fail closed, got %v", err)
			}

			// Switch to a configured Gravit doubleDigest source: this runs
			// through the same real SQL password-authentication path.
			first := sha256.Sum256([]byte("secret"))
			second := sha256.Sum256([]byte(hex.EncodeToString(first[:])))
			_, err = db.ExecContext(ctx, "UPDATE nl_auth_0294_users SET pass_hash="+bind(1)+" WHERE account_id="+bind(2), hex.EncodeToString(second[:]), "42")
			if err != nil {
				t.Fatal(err)
			}
			cfg.Columns.Password = "pass_hash"
			cfg.Password = PasswordConfig{Algorithm: "doubleDigest", AllowLegacyHashes: true, DigestAlgorithm: "SHA256", DigestEncoding: "hex", DoubleDigestHex: true}
			digestConn, err := New(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer digestConn.Close()
			got, err := digestConn.AuthenticatePassword(ctx, authconnector.PasswordRequest{Identifier: "legacy", Secret: "secret"})
			if err != nil || got.Identity.Subject != "42" {
				t.Fatalf("real Gravit doubleDigest login failed: %+v %v", got, err)
			}
		})
	}
	if ran == 0 {
		t.Skip("no live PostgreSQL/MySQL/MariaDB DSNs configured; CI runs all three")
	}
	if os.Getenv("NEVERLAUNCHER_SQL_REQUIRE_ALL") == "1" && ran != 3 {
		t.Fatalf("required 3 live DB engines, got %d", ran)
	}
}
