package sqlconnector

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

func TestGravitLegacyVerifierVectors(t *testing.T) {
	secret := "correct horse"
	sha256Once := sha256.Sum256([]byte(secret))
	sha256DoubleBytes := sha256.Sum256(sha256Once[:])
	sha256DoubleHex := sha256.Sum256([]byte(hex.EncodeToString(sha256Once[:])))
	md5Once := md5.Sum([]byte(secret))
	sha1Once := sha1.Sum([]byte(secret))
	sha512Once := sha512.Sum512([]byte(secret))
	cases := []struct {
		name, hash, mode, digest, encoding string
		hexMode                            bool
	}{
		{"sha256 digest hex", hex.EncodeToString(sha256Once[:]), "digest", "sha256", "hex", false},
		{"sha256 digest base64", base64.StdEncoding.EncodeToString(sha256Once[:]), "digest", "sha256", "base64", false},
		{"md5 digest", hex.EncodeToString(md5Once[:]), "digest", "md5", "hex", false},
		{"sha1 digest", hex.EncodeToString(sha1Once[:]), "digest", "sha1", "hex", false},
		{"sha512 digest", hex.EncodeToString(sha512Once[:]), "digest", "sha512", "hex", false},
		{"double digest bytes", hex.EncodeToString(sha256DoubleBytes[:]), "double-digest", "sha256", "hex", false},
		{"double digest hex", hex.EncodeToString(sha256DoubleHex[:]), "double-digest", "sha256", "hex", true},
		// Cross-checked independently against PHP's portable PHPass reference algorithm.
		{"phpass wordpress", "$P$B12345678QjY5zqJqT433Q3av7QGRM/", "phpass", "", "", false},
		{"phpass drupal", "$H$B12345678QjY5zqJqT433Q3av7QGRM/", "phpass", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := PasswordConfig{Algorithm: tc.mode, AllowLegacyHashes: true, DigestAlgorithm: tc.digest, DigestEncoding: tc.encoding, DoubleDigestHex: tc.hexMode}
			password := secret
			if tc.mode == "phpass" {
				password = "secret"
			}
			ok, err := verifyPassword(password, tc.hash, cfg)
			if err != nil || !ok {
				t.Fatalf("expected known hash valid, ok=%v err=%v", ok, err)
			}
			ok, err = verifyPassword("wrong", tc.hash, cfg)
			if err != nil || ok {
				t.Fatalf("wrong secret accepted, ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestGravitLegacyFailClosed(t *testing.T) {
	cases := []struct {
		hash string
		cfg  PasswordConfig
	}{
		{"$P$B12345678QjY5zqJqT433Q3av7QGRM/", PasswordConfig{Algorithm: "phpass"}},
		{"$P$Z12345678QjY5zqJqT433Q3av7QGRM/", PasswordConfig{Algorithm: "phpass", AllowLegacyHashes: true}},
		{"$P$B12345678QjY5zqJqT433Q3av7QGRM*", PasswordConfig{Algorithm: "phpass", AllowLegacyHashes: true}},
		{"$2y$10$xskAkxff64efsclNY8HUa.BoeuCiSQFbUuLnwNQc8krReAyjtKS3e", PasswordConfig{Algorithm: "phpass", AllowLegacyHashes: true}},
		{strings.Repeat("0", 64), PasswordConfig{Algorithm: "digest", DigestAlgorithm: "sha256", DigestEncoding: "hex"}},
		{"sha256:" + strings.Repeat("0", 64), PasswordConfig{Algorithm: "digest", DigestAlgorithm: "sha256", DigestEncoding: "hex", AllowLegacyHashes: true}},
		{strings.Repeat("0", 64), PasswordConfig{Algorithm: "digest", DigestAlgorithm: "sha512", DigestEncoding: "hex", AllowLegacyHashes: true}},
		{"", PasswordConfig{Algorithm: "unknown", AllowLegacyHashes: true}},
	}
	for i, tc := range cases {
		if ok, err := verifyPassword("secret", tc.hash, tc.cfg); err == nil || ok {
			t.Errorf("case %d accepted unsupported or malformed verifier: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestNormalizeGravitStrictConfiguration(t *testing.T) {
	tls := false
	makeConfig := func() Config {
		return Config{ID: "website", Driver: "postgresql", DSN: "postgres://fixture", Table: "public.users", Columns: Columns{ID: "id", Username: "name", Password: "hash"}, RequireTLS: &tls}
	}
	for _, alg := range []string{"digest", "doubleDigest", "phpass"} {
		c := makeConfig()
		c.Password = PasswordConfig{Algorithm: alg}
		if _, err := Normalize(c); err == nil {
			t.Errorf("unsafe legacy %s without opt-in accepted", alg)
		}
	}
	bad := []PasswordConfig{
		{Algorithm: "digest", AllowLegacyHashes: true},
		{Algorithm: "digest", AllowLegacyHashes: true, DigestAlgorithm: "sha3"},
		{Algorithm: "digest", AllowLegacyHashes: true, DigestAlgorithm: "sha256", DigestEncoding: "auto"},
		{Algorithm: "phpass", AllowLegacyHashes: true, DigestAlgorithm: "md5"},
		{Algorithm: "bcrypt", DigestAlgorithm: "sha256"},
		{Algorithm: "digest", AllowLegacyHashes: true, DigestAlgorithm: "sha256", DoubleDigestHex: true},
	}
	for _, p := range bad {
		c := makeConfig()
		c.Password = p
		if _, err := Normalize(c); err == nil {
			t.Errorf("accepted ambiguous verifier %+v", p)
		}
	}
	good := makeConfig()
	good.Password = PasswordConfig{Algorithm: "doubleDigest", AllowLegacyHashes: true, DigestAlgorithm: "SHA-256", DoubleDigestHex: true}
	runtime, err := Normalize(good)
	if err != nil || runtime.Password.Algorithm != "double-digest" || runtime.Password.DigestAlgorithm != "sha256" {
		t.Fatalf("valid Gravit config rejected: %+v, %v", runtime.Password, err)
	}
}

func TestAuthenticateGravitPHPassFromActualSQLRow(t *testing.T) {
	db, _ := openFixtureDB(t, [][]driver.Value{{"777", "player", "player@example.test", "$P$B12345678QjY5zqJqT433Q3av7QGRM/", "active", "Player", "", "", ""}})
	cfg := testRuntimeConfig(t)
	cfg.Password = PasswordConfig{Algorithm: "phpass", AllowLegacyHashes: true}
	conn, err := newWithDB(context.Background(), cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := conn.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player", Secret: "secret"})
	if err != nil || got.Identity.Subject != "777" {
		t.Fatalf("PHPass database login failed: %+v %v", got, err)
	}
	_, err = conn.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player", Secret: "wrong"})
	if authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("wrong password accepted: %v", err)
	}
}

func TestInspectMappingReadOnlyWithoutReadingHashes(t *testing.T) {
	db, state := openFixtureDB(t, nil)
	cfg := testRuntimeConfig(t)
	mapping, err := InspectMapping(context.Background(), db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(mapping) != 9 || mapping[3].Field != "password" || mapping[3].Column != "password_hash" {
		t.Fatalf("actual SQL mapping not inspected: %+v", mapping)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.readOnlySeen || !strings.Contains(state.query, "WHERE 1 = 0") || strings.Contains(state.query, "SELECT *") {
		t.Fatalf("unsafe schema query: %s readOnly=%v", state.query, state.readOnlySeen)
	}
	if len(state.args) != 0 {
		t.Fatalf("schema inspection included runtime credentials: %+v", state.args)
	}
}
