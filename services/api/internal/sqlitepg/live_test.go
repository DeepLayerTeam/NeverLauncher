package sqlitepg

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestLiveMapping0473(t *testing.T) {
	if _, err := PopulateLive0473(context.Background(), ""); err == nil {
		t.Fatal("accepted empty DSN")
	}
	if _, err := bool0473(int64(2)); err == nil {
		t.Fatal("accepted invalid boolean")
	}
	if b, err := bool0473(int64(0)); err != nil || b != false {
		t.Fatalf("bool: %v %v", b, err)
	}
	if _, err := json0473(`{broken`); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	if _, err := instant0473(int64(-1), false); err == nil {
		t.Fatal("accepted negative timestamp")
	}
	if v, err := instant0473(int64(0), true); err != nil || v != nil {
		t.Fatalf("optional zero: %v %v", v, err)
	}
	if v, err := instant0473(int64(1), false); err != nil || !v.(time.Time).Equal(time.Unix(0, 1)) {
		t.Fatalf("nanoseconds: %v %v", v, err)
	}
	for _, r := range rules0473() {
		if r.source == "" || r.target == "" || len(r.columns) == 0 {
			t.Fatalf("incomplete live mapping: %+v", r)
		}
	}
	if err := checkManifest0473(map[string]any{"manifest": "{}", "status": "published"}); err == nil {
		t.Fatal("invalid manifest accepted")
	}
}

// Выполнять ТОЛЬКО с изолированной пустой тестовой БД PostgreSQL под управлением CI.
// Интеграционный тест применяет реальные встроенные миграции и читает через
// SQLRepository, а не промежуточные таблицы или имитацию БД.
func TestLiveSQLiteToSQLRepository0473(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_PG_LIVE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated LAUNCHER_PG_LIVE_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var empty bool
	err = pg.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, Schema).Scan(&empty)
	_ = pg.Close(ctx)
	if err != nil || !empty {
		t.Fatalf("must be a dedicated, untouched PostgreSQL test database: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = dbmigrate.Apply(ctx, db); err != nil {
		t.Fatalf("apply real PostgreSQL schema: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "core.db")
	backup := filepath.Join(dir, "core-backup.db")
	core, err := sqlitecore.Open(ctx, sqlitedurable.Options{Path: src})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveProject(ctx, model.Project{ID: "project-47", Name: "Imported Project"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveProfile(ctx, model.Profile{ID: "vanilla-1", ProjectID: "project-47", Name: "Vanilla 1", Loader: "vanilla", MinecraftVersion: "1.21.1", JavaMajor: 21}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SaveUser(ctx, model.User{ID: "u1", Email: "owner@example.test", DisplayName: "Owner", RoleID: "owner", Status: "active", PasswordHash: "persisted-password-hash"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := core.CreateDraft(ctx, "project-47", "vanilla-1", "stable", "1.0.0", "test")
	if err != nil {
		t.Fatal(err)
	}
	draft.Manifest.Files = []model.ManifestFile{{Path: "mods/example.jar", Size: 128, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", URL: "https://example.test/files/example.jar", Required: true, Ownership: "required", Mirrors: []string{"https://mirror.example.test/example.jar"}}}
	if _, err = core.UpdateDraftManifest(ctx, "project-47", draft.ID, draft.Manifest, "test"); err != nil {
		t.Fatal(err)
	}
	if err = core.Close(); err != nil {
		t.Fatal(err)
	}
	// Проверять настоящие транзакционные строки состояния, а не только проекты/профили.
	rawDB, er := sql.Open("sqlite", src)
	if er != nil {
		t.Fatal(er)
	}
	now := time.Now().UTC().UnixNano()
	execRaw := func(q string, args ...any) {
		t.Helper()
		if _, x := rawDB.Exec(q, args...); x != nil {
			t.Fatalf("SQLite fixture %s: %v", q, x)
		}
	}
	execRaw(`UPDATE users SET auth_epoch=2 WHERE id='u1'`)
	execRaw(`INSERT INTO auth_sessions(id,user_id,auth_epoch,device_id,status,auth_methods,created_at,last_seen_at,expires_at)
        VALUES('session-47','u1',2,'desktop','active','["password"]',?,?,?)`, now, now, now+int64(time.Hour))
	mfaKey := make([]byte, 32)
	for i := range mfaKey {
		mfaKey[i] = 0x42
	}
	mfaSeed := make([]byte, 20)
	for i := range mfaSeed {
		mfaSeed[i] = 0x37
	}
	mfaBlock, er := aes.NewCipher(mfaKey)
	if er != nil {
		t.Fatal(er)
	}
	mfaAEAD, er := cipher.NewGCM(mfaBlock)
	if er != nil {
		t.Fatal(er)
	}
	mfaNonce := make([]byte, mfaAEAD.NonceSize())
	if _, er = rand.Read(mfaNonce); er != nil {
		t.Fatal(er)
	}
	mfaCoreCipher := mfaAEAD.Seal(mfaNonce, mfaNonce, mfaSeed, []byte("Launcher/TOTP/0.32.3"))
	execRaw(`INSERT INTO mfa_totp(user_id,status,secret_ciphertext,last_step,created_at,updated_at) VALUES('u1','active',?,-1,?,?)`, mfaCoreCipher, now, now)
	recoveryCode := strings.Repeat("A", 16)
	recoveryHash := sha256.Sum256([]byte(recoveryCode))
	execRaw(`INSERT INTO mfa_recovery(code_hash,user_id,created_at) VALUES(?,'u1',?)`, hex.EncodeToString(recoveryHash[:]), now)
	execRaw(`INSERT INTO refresh_families(id,session_id,status,created_at) VALUES('family-47','session-47','active',?)`, now)
	execRaw(`INSERT INTO refresh_tokens(token_hash,family_id,status,created_at,expires_at) VALUES(?, 'family-47','current',?,?)`, strings.Repeat("a", 64), now, now+int64(time.Hour))
	execRaw(`INSERT INTO durable_scope_leases(scope_key,owner,lease_token,fencing_token,expires_at,updated_at)
        VALUES('scope-47','sqlite-worker',?,17,?,?)`, strings.Repeat("f", 64), now+int64(time.Hour), now)
	digest := sha256.Sum256([]byte(`{}`))
	execRaw(`INSERT INTO durable_jobs(id,kind,actor_type,actor_id,action,resource_type,resource_id,idempotency_key,payload,payload_digest,status,max_attempts,available_at,created_at,updated_at)
        VALUES('job-47','publish','user','u1','release:publish','release','release-47','idem-47','{}',?,'pending',3,?,?,?)`, hex.EncodeToString(digest[:]), now, now, now)
	execRaw(`INSERT INTO durable_outbox(id,event_type,aggregate_type,aggregate_id,idempotency_key,payload,payload_digest,status,max_attempts,available_at,created_at,updated_at)
        VALUES('event-47','publish','release','release-47','event-idem-47','{}',?,'pending',3,?,?,?)`, hex.EncodeToString(digest[:]), now, now, now)
	pub, _, er := ed25519.GenerateKey(rand.Reader)
	if er != nil {
		t.Fatal(er)
	}
	fp := sha256.Sum256(pub)
	execRaw(`INSERT INTO bridge_nodes(id,project_id,profile_id,channel,public_key,fingerprint,identity_epoch,status,created_at,updated_at)
        VALUES('bridge-47','project-47','vanilla-1','stable',?,?,3,'active',?,?)`, []byte(pub), hex.EncodeToString(fp[:]), now, now)
	execRaw(`INSERT INTO bridge_nonces(node_id,identity_epoch,nonce_hash,action,committed_at,expires_at)
        VALUES('bridge-47',3,?,'ping',?,?)`, strings.Repeat("e", 64), now, now+int64(time.Minute))
	if er = rawDB.Close(); er != nil {
		t.Fatal(er)
	}
	if _, err = sqlitedurable.OnlineBackup(ctx, src, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = Import(ctx, backup, dsn); err != nil {
		t.Fatalf("staging: %v", err)
	}
	live, err := PopulateLiveWithMFA0474(ctx, dsn, MFASecrets0474{SQLiteMFAKey: mfaKey, PostgreSQLSecret: "postgres-mfa-integration-key"})
	if err != nil {
		t.Fatalf("LIVE conversion: %v", err)
	}
	if !live.Verified || live.ReadyForBackendCutover || live.Files != 1 || live.LocalIdentities != 1 || len(live.LiveTables) != len(rules0473())+len(stateRules0474()) {
		t.Fatalf("incorrect live receipt: %+v", live)
	}
	api := repository.NewPostgresRepository(dsn, "")
	project, err := api.GetProject("project-47")
	if err != nil || project.Name != "Imported Project" {
		t.Fatalf("SQLRepository project: %+v %v", project, err)
	}
	profiles, err := api.ListProfiles("project-47")
	if err != nil || len(profiles) != 1 || profiles[0].MinecraftVersion != "1.21.1" || profiles[0].JavaMajor != 21 {
		t.Fatalf("SQLRepository profiles: %+v %v", profiles, err)
	}
	versions, err := api.ListVersions("project-47")
	if err != nil || len(versions) != 1 || versions[0].Manifest.ProfileSnapshot == nil {
		t.Fatalf("SQLRepository versions: %+v %v", versions, err)
	}
	u, err := api.GetUserByEmail("owner@example.test")
	if err != nil || u.ID != "u1" || u.PasswordHash != "persisted-password-hash" {
		t.Fatalf("SQLRepository user: %+v %v", u, err)
	}
	pg2, er := pgx.Connect(ctx, dsn)
	if er != nil {
		t.Fatal(er)
	}
	var identityUser string
	er = pg2.QueryRow(ctx, `SELECT user_id FROM auth_identities WHERE provider='local' AND subject='u1'`).Scan(&identityUser)
	var importedEpoch, scopeFence int64
	var sessionStatus, scopeToken string
	er = pg2.QueryRow(ctx, `SELECT core_auth_epoch_0474,status FROM auth_sessions WHERE id='session-47'`).Scan(&importedEpoch, &sessionStatus)
	if er != nil || importedEpoch != 2 || sessionStatus != "revoked" {
		t.Fatalf("session not rotated: %d %s %v", importedEpoch, sessionStatus, er)
	}
	var methodStatus, pgCipher string
	er = pg2.QueryRow(ctx, `SELECT status,active_secret_ciphertext FROM mfa_methods WHERE id='mfa-totp-u1'`).Scan(&methodStatus, &pgCipher)
	if er != nil || methodStatus != "enabled" {
		t.Fatalf("mfa disabled on import: %s %v", methodStatus, er)
	}
	mfaCipherBytes, er := base64.RawURLEncoding.DecodeString(pgCipher)
	if er != nil {
		t.Fatal(er)
	}
	pgMFAKey := sha256.Sum256([]byte("postgres-mfa-integration-key"))
	pgBlock, er := aes.NewCipher(pgMFAKey[:])
	if er != nil {
		t.Fatal(er)
	}
	pgAEAD, er := cipher.NewGCM(pgBlock)
	if er != nil {
		t.Fatal(er)
	}
	mfaUnwrapped, er := pgAEAD.Open(nil, mfaCipherBytes[:pgAEAD.NonceSize()], mfaCipherBytes[pgAEAD.NonceSize():], []byte("0.10.0"))
	if er != nil || string(mfaUnwrapped) != base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mfaSeed) {
		t.Fatalf("imported MFA key is not equivalent: %v", er)
	}
	var importedRecovery string
	er = pg2.QueryRow(ctx, `SELECT code_hash FROM recovery_codes WHERE user_id='u1' AND method_id='mfa-totp-u1'`).Scan(&importedRecovery)
	if er != nil || importedRecovery != hex.EncodeToString(recoveryHash[:]) {
		t.Fatalf("recovery code mismatch: %s %v", importedRecovery, er)
	}
	er = pg2.QueryRow(ctx, `SELECT fencing_token,lease_token FROM durable_scope_leases WHERE scope_key='scope-47'`).Scan(&scopeFence, &scopeToken)
	if er != nil || scopeFence != 18 || scopeToken != "" {
		t.Fatalf("scope not fenced: %d %s %v", scopeFence, scopeToken, er)
	}
	for _, q := range []string{`SELECT id FROM durable_jobs WHERE id='job-47'`, `SELECT id FROM event_outbox WHERE id='event-47'`, `SELECT id FROM server_bridge_nodes_v2 WHERE id='bridge-47'`, `SELECT id FROM refresh_token_families WHERE id='family-47'`} {
		var id string
		if er = pg2.QueryRow(ctx, q).Scan(&id); er != nil {
			t.Fatalf("SQLRepository state not readable: %s %v", q, er)
		}
	}
	pg2.Close(ctx)
	if er != nil || identityUser != "u1" {
		t.Fatalf("SQLRepository local login identity: %s %v", identityUser, er)
	}
	if _, err = PopulateLive0473(ctx, dsn); err == nil {
		t.Fatal("reimport over live database accepted")
	}
	files, err := api.ListFiles("project-47", versions[0].ID)
	if err != nil || len(files) != 1 || files[0].Path != "mods/example.jar" || files[0].URL != "https://example.test/files/example.jar" || len(files[0].Mirrors) != 1 || files[0].Mirrors[0] != "https://mirror.example.test/example.jar" {
		t.Fatalf("SQLRepository file links: %+v %v", files, err)
	}
}
