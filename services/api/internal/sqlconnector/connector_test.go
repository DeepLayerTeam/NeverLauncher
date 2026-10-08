package sqlconnector

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type fixtureState struct {
	mu           sync.Mutex
	rows         [][]driver.Value
	readOnlySeen bool
	query        string
	args         []driver.NamedValue
}

type fixtureDriver struct{ states *sync.Map }
type fixtureConn struct{ state *fixtureState }
type fixtureStmt struct {
	state *fixtureState
	query string
}

type fixtureTx struct{}
type fixtureRows struct {
	rows  [][]driver.Value
	index int
}

func (d fixtureDriver) Open(name string) (driver.Conn, error) {
	value, _ := d.states.Load(name)
	return &fixtureConn{state: value.(*fixtureState)}, nil
}
func (c *fixtureConn) Prepare(query string) (driver.Stmt, error) {
	return &fixtureStmt{state: c.state, query: query}, nil
}
func (c *fixtureConn) Close() error              { return nil }
func (c *fixtureConn) Begin() (driver.Tx, error) { return fixtureTx{}, nil }
func (c *fixtureConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.state.mu.Lock()
	c.state.readOnlySeen = opts.ReadOnly
	c.state.mu.Unlock()
	return fixtureTx{}, nil
}
func (c *fixtureConn) Ping(context.Context) error { return nil }
func (c *fixtureConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	c.state.query = query
	c.state.args = append([]driver.NamedValue(nil), args...)
	rows := make([][]driver.Value, len(c.state.rows))
	for i := range c.state.rows {
		rows[i] = append([]driver.Value(nil), c.state.rows[i]...)
	}
	c.state.mu.Unlock()
	return &fixtureRows{rows: rows}, nil
}
func (s *fixtureStmt) Close() error                               { return nil }
func (s *fixtureStmt) NumInput() int                              { return -1 }
func (s *fixtureStmt) Exec([]driver.Value) (driver.Result, error) { return nil, driver.ErrSkip }
func (s *fixtureStmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, value := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	return s.QueryContext(context.Background(), named)
}
func (s *fixtureStmt) QueryContext(_ context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.state.mu.Lock()
	s.state.query = s.query
	s.state.args = append([]driver.NamedValue(nil), args...)
	rows := make([][]driver.Value, len(s.state.rows))
	for i := range s.state.rows {
		rows[i] = append([]driver.Value(nil), s.state.rows[i]...)
	}
	s.state.mu.Unlock()
	return &fixtureRows{rows: rows}, nil
}

func (fixtureTx) Commit() error   { return nil }
func (fixtureTx) Rollback() error { return nil }
func (r *fixtureRows) Columns() []string {
	return []string{"id", "username", "email", "password", "status", "display_name", "groups", "roles", "minecraft_uuid"}
}
func (r *fixtureRows) Close() error { return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

var (
	registerFixtureDriver sync.Once
	fixtureStates         sync.Map
)

func openFixtureDB(t *testing.T, rows [][]driver.Value) (*sql.DB, *fixtureState) {
	t.Helper()
	registerFixtureDriver.Do(func() { sql.Register("neverlauncher-sqlconnector-test", fixtureDriver{states: &fixtureStates}) })
	key := strings.ReplaceAll(t.Name(), "/", "-") + time.Now().Format("150405.000000000")
	state := &fixtureState{rows: rows}
	fixtureStates.Store(key, state)
	t.Cleanup(func() { fixtureStates.Delete(key) })
	db, err := sql.Open("neverlauncher-sqlconnector-test", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, state
}

func testRuntimeConfig(t *testing.T) RuntimeConfig {
	t.Helper()
	allowTLS := false
	hash := sha256.Sum256([]byte("secret"))
	_ = hash
	cfg, err := Normalize(Config{
		ID: "website", DisplayName: "Website SQL", Driver: "postgresql", DSN: "postgres://fixture", Table: "public.users",
		Columns:  Columns{ID: "id", Username: "username", Email: "email", Password: "password_hash", Status: "status", DisplayName: "display_name", Groups: "groups", Roles: "roles", MinecraftUUID: "minecraft_uuid"},
		Password: PasswordConfig{Algorithm: "legacy-sha256", AllowLegacySHA256: true}, RequireTLS: &allowTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAuthenticatePasswordQueriesReadOnlyAndMapsIdentity(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	db, state := openFixtureDB(t, [][]driver.Value{{"42", "player", "player@example.test", "sha256:" + hex.EncodeToString(sum[:]), "active", "Player 42", `["builders","vip"]`, "member,premium", "550e8400-e29b-41d4-a716-446655440000"}})
	cfg := testRuntimeConfig(t)
	connector, err := newWithDB(context.Background(), cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player@example.test", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Identity.Subject != "42" || auth.Identity.Email != "player@example.test" || auth.Identity.DisplayName != "Player 42" {
		t.Fatalf("unexpected identity: %+v", auth.Identity)
	}
	if len(auth.Identity.Groups) != 2 || len(auth.Identity.Roles) != 2 {
		t.Fatalf("mapping lost: %+v", auth.Identity)
	}
	if auth.Identity.Claims["minecraftUuid"] != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("minecraft UUID not mapped: %+v", auth.Identity.Claims)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.readOnlySeen {
		t.Fatal("connector did not request a read-only transaction")
	}
	if strings.Contains(state.query, "player@example.test") || strings.Contains(state.query, "secret") {
		t.Fatalf("credentials interpolated into SQL: %s", state.query)
	}
	if len(state.args) != 1 || state.args[0].Value != "player@example.test" {
		t.Fatalf("expected one PostgreSQL bind argument, got %+v", state.args)
	}
}

func TestAuthenticatePasswordRejectsDuplicateIdentifier(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	hash := "sha256:" + hex.EncodeToString(sum[:])
	db, _ := openFixtureDB(t, [][]driver.Value{
		{"1", "same", "a@example.test", hash, "active", "A", "", "", ""},
		{"2", "other", "same", hash, "active", "B", "", "", ""},
	})
	connector, err := newWithDB(context.Background(), testRuntimeConfig(t), db)
	if err != nil {
		t.Fatal(err)
	}
	_, err = connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "same", Secret: "secret"})
	if authconnector.CodeOf(err) != authconnector.ErrConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestPasswordAlgorithms(t *testing.T) {
	if ok, err := verifyPassword("correct horse battery staple", "$2y$10$xskAkxff64efsclNY8HUa.BoeuCiSQFbUuLnwNQc8krReAyjtKS3e", PasswordConfig{Algorithm: "bcrypt"}); err != nil || !ok {
		t.Fatalf("bcrypt verification failed ok=%v err=%v", ok, err)
	}
	salt := []byte("neverlauncher-test-salt")
	derived := pbkdf2SHA256([]byte("secret"), salt, 12000, 32)
	encoded := "$pbkdf2-sha256$12000$" + rawBase64(salt) + "$" + rawBase64(derived)
	if ok, err := verifyPassword("secret", encoded, PasswordConfig{Algorithm: "pbkdf2-sha256", PBKDF2MinIterations: 10000}); err != nil || !ok {
		t.Fatalf("PBKDF2 verification failed ok=%v err=%v", ok, err)
	}
	sum := sha256.Sum256([]byte("legacy"))
	if ok, err := verifyPassword("legacy", "sha256:"+hex.EncodeToString(sum[:]), PasswordConfig{Algorithm: "legacy-sha256", AllowLegacySHA256: true}); err != nil || !ok {
		t.Fatalf("legacy SHA-256 verification failed ok=%v err=%v", ok, err)
	}
}

func rawBase64(input []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Small local encoder keeps this test independent from implementation helpers.
	out := make([]byte, 0, (len(input)*8+5)/6)
	var buffer uint32
	bits := 0
	for _, b := range input {
		buffer = (buffer << 8) | uint32(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, alphabet[(buffer>>bits)&0x3f])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(buffer<<(6-bits))&0x3f])
	}
	return string(out)
}

func TestNormalizeRejectsUnsafeIdentifiersAndLegacySHAByDefault(t *testing.T) {
	requireTLS := false
	_, err := Normalize(Config{ID: "sql", Driver: "postgresql", DSN: "x", Table: "users; DROP TABLE users", Columns: Columns{ID: "id", Email: "email", Password: "password"}, Password: PasswordConfig{Algorithm: "bcrypt"}, RequireTLS: &requireTLS})
	if err == nil {
		t.Fatal("unsafe table identifier accepted")
	}
	_, err = Normalize(Config{ID: "sql", Driver: "postgresql", DSN: "x", Table: "users", Columns: Columns{ID: "id", Email: "email", Password: "password"}, Password: PasswordConfig{Algorithm: "sha256"}, RequireTLS: &requireTLS})
	if err == nil {
		t.Fatal("legacy SHA-256 enabled without explicit opt-in")
	}
}

func TestParseStringListSupportsPostgresTextArrays(t *testing.T) {
	values, err := parseStringList(`{"builders","ops,team","quoted\"name",NULL,"NULL"}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"builders", "ops,team", `quoted"name`, "NULL"}
	if len(values) != len(want) {
		t.Fatalf("unexpected values: %#v", values)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value %d: want %q got %q (%#v)", i, want[i], values[i], values)
		}
	}
	if _, err := parseStringList(`{"broken}`); err == nil {
		t.Fatal("malformed PostgreSQL array accepted")
	}
	if _, err := parseStringList(`{{"nested"}}`); err == nil {
		t.Fatal("nested PostgreSQL array accepted")
	}
}

func TestTLSPolicyRejectsPlaintextFallback(t *testing.T) {
	requireTLS := true
	cfg, err := Normalize(Config{ID: "pg", Driver: "postgresql", DSN: "postgres://db.example/test?sslmode=prefer", Table: "users", Columns: Columns{ID: "id", Email: "email", Password: "password"}, Password: PasswordConfig{Algorithm: "bcrypt"}, RequireTLS: &requireTLS, AllowInsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresTLS(cfg); err == nil {
		t.Fatal("PostgreSQL sslmode=prefer accepted while TLS is required")
	}
	cfg.DSN = "postgres://db.example/test?sslmode=require"
	if err := validatePostgresTLS(cfg); err != nil {
		t.Fatalf("PostgreSQL sslmode=require should be accepted only with explicit allowInsecureTls: %v", err)
	}
	cfg.AllowInsecureTLS = false
	if err := validatePostgresTLS(cfg); err == nil {
		t.Fatal("PostgreSQL sslmode=require accepted without certificate verification opt-in")
	}
	cfg.DSN = "postgres://db.example/test?sslmode=verify-full"
	if err := validatePostgresTLS(cfg); err != nil {
		t.Fatalf("PostgreSQL verify-full rejected: %v", err)
	}

	mysqlCfg := cfg
	mysqlCfg.Driver = "mysql"
	mysqlCfg.AllowInsecureTLS = true
	if err := validateMySQLTLSMode(mysqlCfg, "preferred"); err == nil {
		t.Fatal("MySQL tls=preferred accepted while TLS is required")
	}
	if err := validateMySQLTLSMode(mysqlCfg, "skip-verify"); err != nil {
		t.Fatalf("MySQL tls=skip-verify rejected with explicit allowInsecureTls: %v", err)
	}
	mysqlCfg.AllowInsecureTLS = false
	if err := validateMySQLTLSMode(mysqlCfg, "skip-verify"); err == nil {
		t.Fatal("MySQL tls=skip-verify accepted without insecure TLS opt-in")
	}
	if err := validateMySQLTLSMode(mysqlCfg, "true"); err != nil {
		t.Fatalf("MySQL tls=true rejected: %v", err)
	}
}

func TestPasswordAlgorithmsArgon2AndDjangoPBKDF2(t *testing.T) {
	argonHash := `$argon2id$v=19$m=8192,t=2,p=1$4PsCctcmsXex95yvydR9kA$wPiBZmNgGrZqbmIKX2RXNJG99bhcgZ/fXwEzO9MGras`
	if ok, err := verifyPassword("secret", argonHash, PasswordConfig{Algorithm: "argon2id"}); err != nil || !ok {
		t.Fatalf("Argon2id verification failed ok=%v err=%v", ok, err)
	}
	if ok, err := verifyPassword("wrong", argonHash, PasswordConfig{Algorithm: "argon2id"}); err != nil || ok {
		t.Fatalf("Argon2id wrong password accepted ok=%v err=%v", ok, err)
	}

	salt := "django-test-salt"
	derived := pbkdf2SHA256([]byte("secret"), []byte(salt), 12000, 32)
	django := "pbkdf2_sha256$12000$" + salt + "$" + rawBase64(derived)
	if ok, err := verifyPassword("secret", django, PasswordConfig{Algorithm: "pbkdf2-sha256", PBKDF2MinIterations: 10000}); err != nil || !ok {
		t.Fatalf("Django PBKDF2 verification failed ok=%v err=%v", ok, err)
	}
}

func TestBuildQueriesUsesDriverPlaceholders(t *testing.T) {
	pg := testRuntimeConfig(t)
	query, _, args, err := buildQueries(pg)
	if err != nil {
		t.Fatal(err)
	}
	if args != 1 || strings.Count(query, "$1") != 2 || strings.Contains(query, "?") {
		t.Fatalf("unexpected PostgreSQL query/args: args=%d query=%s", args, query)
	}

	mysql := pg
	mysql.Driver = "mysql"
	query, _, args, err = buildQueries(mysql)
	if err != nil {
		t.Fatal(err)
	}
	if args != 2 || strings.Count(query, "?") != 2 || strings.Contains(query, "$1") {
		t.Fatalf("unexpected MySQL query/args: args=%d query=%s", args, query)
	}
}

func TestAuthenticatePasswordRejectsDisabledIdentity(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	db, _ := openFixtureDB(t, [][]driver.Value{{"42", "player", "player@example.test", "sha256:" + hex.EncodeToString(sum[:]), "disabled", "Player", "", "", ""}})
	connector, err := newWithDB(context.Background(), testRuntimeConfig(t), db)
	if err != nil {
		t.Fatal(err)
	}
	_, err = connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player", Secret: "secret"})
	if authconnector.CodeOf(err) != authconnector.ErrIdentityDisabled {
		t.Fatalf("expected disabled identity error, got %v", err)
	}
}

func TestNormalizeRejectsAmbiguousDSNAndExcessivePool(t *testing.T) {
	requireTLS := false
	base := Config{ID: "sql", Driver: "postgresql", DSN: "postgres://one", DSNEnv: "OTHER_DSN", Table: "users", Columns: Columns{ID: "id", Email: "email", Password: "password"}, Password: PasswordConfig{Algorithm: "bcrypt"}, RequireTLS: &requireTLS}
	if _, err := Normalize(base); err == nil {
		t.Fatal("configuration with both dsn and dsnEnv was accepted")
	}
	base.DSNEnv = ""
	base.MaxOpenConns = 513
	if _, err := Normalize(base); err == nil {
		t.Fatal("excessive SQL connection pool was accepted")
	}
}
