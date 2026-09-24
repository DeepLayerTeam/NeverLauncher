package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

const persistenceSchema950 = "0.10.0"

type persistenceSnapshot950 struct {
	AuthSessions []authSessionRecord  `json:"authSessions"`
	Security     securityState950     `json:"security"`
	ServerBridge serverBridgeState950 `json:"serverBridge"`
	ExportedAt   time.Time            `json:"exportedAt"`
}

type securityState950 struct {
	MFA            map[string]mfaPersistRecord950  `json:"mfa"`
	FailedLogins   map[string]loginFailureRecord   `json:"failedLogins"`
	PasswordResets map[string]oneTimeSecurityToken `json:"passwordResets"`
	EmailTokens    map[string]oneTimeSecurityToken `json:"emailTokens"`
	EmailVerified  map[string]bool                 `json:"emailVerified"`
	RecoveryUseLog []map[string]any                `json:"recoveryUseLog"`
}

type mfaPersistRecord950 struct {
	PendingSecretEncrypted string            `json:"pendingSecretEncrypted,omitempty"`
	ActiveSecretEncrypted  string            `json:"activeSecretEncrypted,omitempty"`
	Enabled                bool              `json:"enabled"`
	Recovery               map[string]string `json:"recovery"`
	UpdatedAt              time.Time         `json:"updatedAt"`
}

type serverBridgeState950 struct {
	Servers  map[string]bridgeServerRecord  `json:"servers"`
	Joins    map[string]bridgeJoinRecord    `json:"joins"`
	Textures map[string]bridgeTextureRecord `json:"textures"`
}

type persistenceSQL950 struct {
	driverName string
	dsn        string
}

func ValidatePersistenceConfig950(cfg config.Config) error {
	if !cfg.RequirePersistentStoreInProduction {
		return nil
	}
	if isProduction950(cfg.Environment) && isMemoryRepository950(cfg.RepositoryDriver) {
		return errors.New("production mode требует NEVERLAUNCHER_REPOSITORY_DRIVER=postgres: memory repository запрещён для 0.10.0 persistence")
	}
	return nil
}

func BootstrapPersistence950(cfg config.Config, state *RuntimeState) error {
	if isMemoryRepository950(cfg.RepositoryDriver) {
		return nil
	}
	store := persistenceSQL950{driverName: firstNonEmpty(cfg.SQLDriver, "pgx"), dsn: cfg.DatabaseDSN}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := store.ensure(ctx); err != nil {
		return err
	}
	if snapshot, ok, err := store.loadLatest(ctx, "all"); err != nil {
		return err
	} else if ok {
		if err := importPersistenceSnapshot950(state, snapshot, cfg.AuthTokenSecret); err != nil {
			return err
		}
	}
	return nil
}

func (s Server) ecosystemPersistence(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": s.persistencePayload950("ecosystem")})
}

func (s Server) persistenceStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": s.persistencePayload950("status")})
}

func (s Server) persistenceReadiness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": s.persistencePayload950("readiness")})
}

func (s Server) persistenceSecurity(w http.ResponseWriter, r *http.Request) {
	payload := s.persistencePayload950("security")
	payload["securityState"] = s.State.Security.export950(s.Config.AuthTokenSecret)
	payload["authSessions"] = s.State.AuthSessions.summary()
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": payload})
}

func (s Server) persistenceServerBridge(w http.ResponseWriter, r *http.Request) {
	payload := s.persistencePayload950("server-bridge")
	payload["serverBridgeState"] = s.State.ServerBridge.summary()
	payload["servers"] = s.State.ServerBridge.listServers()
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": payload})
}

func (s Server) persistenceSmoke(w http.ResponseWriter, r *http.Request) {
	payload := s.persistencePayload950("smoke")
	status := "passed"
	checks := []map[string]any{}
	add := func(id, st, message string) {
		if st != "ok" {
			status = "degraded"
		}
		checks = append(checks, map[string]any{"id": id, "status": st, "message": message})
	}
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		if isProduction950(s.Config.Environment) {
			add("repository", "failed", "production mode forbids memory repository")
		} else {
			add("repository", "ok", "memory repository accepted for dev/test smoke")
		}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		store := persistenceSQL950{driverName: firstNonEmpty(s.Config.SQLDriver, "pgx"), dsn: s.Config.DatabaseDSN}
		if err := store.ensure(ctx); err != nil {
			add("postgres-ddl", "failed", err.Error())
		} else if err := store.save(ctx, "all", exportPersistenceSnapshot950(s.State, s.Config.AuthTokenSecret)); err != nil {
			add("postgres-write", "failed", err.Error())
		} else if _, ok, err := store.loadLatest(ctx, "all"); err != nil || !ok {
			add("postgres-read", "failed", fmt.Sprintf("ok=%v err=%v", ok, err))
		} else {
			add("postgres-ddl-write-read", "ok", "snapshot persisted and loaded")
		}
	}
	payload["status"] = status
	payload["checks"] = checks
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": persistenceSchema950, "data": payload})
}

func (s Server) persistencePayload950(kind string) map[string]any {
	status := "persistent-ready"
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		if isProduction950(s.Config.Environment) {
			status = "failed-production-memory-store"
		} else {
			status = "dev-memory-store"
		}
	}
	payload := map[string]any{
		"schemaVersion": persistenceSchema950,
		"toolVersion":   s.Version,
		"kind":          kind,
		"release":       "NeverLauncher 0.10.0 Persisted PostgreSQL State",
		"mode":          "postgres-backed-security-serverbridge-state",
		"status":        status,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"repository": map[string]any{
			"driver":         s.Config.RepositoryDriver,
			"sqlDriver":      s.Config.SQLDriver,
			"databaseDsn":    redactDSN950(s.Config.DatabaseDSN),
			"environment":    s.Config.Environment,
			"productionGate": s.Config.RequirePersistentStoreInProduction,
		},
		"implemented": []string{
			"PostgreSQL DDL for security users, normalized auth sessions/token families/MFA, bridge servers, join sessions, textures and audit",
			"normalized PostgreSQL auth core is source of truth for sessions and MFA in 0.11.1",
			"JSON persistence snapshots remain for non-auth legacy state and 0.10.x migration bootstrap",
			"startup migration from latest PostgreSQL persistence snapshot into normalized auth tables",
			"production guard: memory repository is rejected when NEVERLAUNCHER_ENV=production",
			"persistence status/readiness/security/server-bridge/smoke endpoints",
			"backup/restore manifests include 0.10.0 persistent state tables",
		},
		"endpoints": []string{
			"GET /ready",
			"GET /ready",
			"GET /ready",
			"GET /api/v1/operations/compliance",
			"GET /api/v1/server-bridge/diagnostics",
			"GET /api/v1/operations/diagnostics",
		},
		"persistentState": exportPersistenceSummary950(s.State),
	}
	if kind == "readiness" {
		payload["checks"] = []map[string]string{
			{"id": "production-memory-gate", "status": boolStatus950(!(isProduction950(s.Config.Environment) && isMemoryRepository950(s.Config.RepositoryDriver)))},
			{"id": "security-state-export", "status": "ok"},
			{"id": "server-bridge-state-export", "status": "ok"},
			{"id": "auth-session-state-export", "status": "ok"},
			{"id": "postgres-ddl", "status": "available"},
		}
	}
	return payload
}

func (s Server) flushPersistenceState950(reason string) error {
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	store := persistenceSQL950{driverName: firstNonEmpty(s.Config.SQLDriver, "pgx"), dsn: s.Config.DatabaseDSN}
	if err := store.ensure(ctx); err != nil {
		return err
	}
	snapshot := exportPersistenceSnapshot950(s.State, s.Config.AuthTokenSecret)
	return store.save(ctx, "all", snapshot)
}

func (p persistenceSQL950) open() (*sql.DB, error) {
	if strings.TrimSpace(p.dsn) == "" {
		return nil, errors.New("database dsn пуст")
	}
	driver := strings.TrimSpace(p.driverName)
	if driver == "" {
		driver = "pgx"
	}
	return sql.Open(driver, p.dsn)
}

func (p persistenceSQL950) ensure(ctx context.Context) error {
	db, err := p.open()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	for _, stmt := range persistenceDDL950() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (p persistenceSQL950) save(ctx context.Context, kind string, snapshot persistenceSnapshot950) error {
	db, err := p.open()
	if err != nil {
		return err
	}
	defer db.Close()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO neverlauncher_persistence_snapshots_950 (kind, schema_version, payload, created_at) VALUES ($1,$2,$3,$4)`, kind, persistenceSchema950, string(payload), time.Now().UTC())
	return err
}

func (p persistenceSQL950) loadLatest(ctx context.Context, kind string) (persistenceSnapshot950, bool, error) {
	db, err := p.open()
	if err != nil {
		return persistenceSnapshot950{}, false, err
	}
	defer db.Close()
	var raw string
	err = db.QueryRowContext(ctx, `SELECT payload::text FROM neverlauncher_persistence_snapshots_950 WHERE kind = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, kind).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return persistenceSnapshot950{}, false, nil
	}
	if err != nil {
		return persistenceSnapshot950{}, false, err
	}
	var snapshot persistenceSnapshot950
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return persistenceSnapshot950{}, false, err
	}
	return snapshot, true, nil
}

func persistenceDDL950() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS neverlauncher_persistence_snapshots_950 (id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, schema_version TEXT NOT NULL, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS idx_neverlauncher_persistence_snapshots_950_kind_created ON neverlauncher_persistence_snapshots_950 (kind, created_at DESC)`,
	}
}

func exportPersistenceSnapshot950(state *RuntimeState, secret string) persistenceSnapshot950 {
	return persistenceSnapshot950{AuthSessions: state.AuthSessions.export950(), Security: state.Security.export950(secret), ServerBridge: state.ServerBridge.export950(), ExportedAt: time.Now().UTC()}
}

func importPersistenceSnapshot950(state *RuntimeState, snapshot persistenceSnapshot950, secret string) error {
	if err := state.AuthSessions.import950(snapshot.AuthSessions); err != nil {
		return err
	}
	if err := state.Security.import950(snapshot.Security, secret); err != nil {
		return err
	}
	state.ServerBridge.import950(snapshot.ServerBridge)
	return nil
}

func exportPersistenceSummary950(state *RuntimeState) map[string]any {
	return map[string]any{
		"authSessions": state.AuthSessions.summary(),
		"security":     state.Security.summary(),
		"passkeys":     state.Passkeys.summary(),
		"serverBridge": state.ServerBridge.summary(),
	}
}

func (s *authSessionStore) export950() []authSessionRecord {
	if s.persistent != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]authSessionRecord, 0, len(s.sessions))
	for _, item := range s.sessions {
		items = append(items, item)
	}
	return items
}

func (s *authSessionStore) import950(items []authSessionRecord) error {
	if s.persistent != nil {
		return s.persistent.importLegacySessions(items)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]authSessionRecord{}
	}
	for _, item := range items {
		if item.ID != "" {
			s.sessions[item.ID] = item
		}
	}
	return nil
}

func (s *securityHardeningStore) export950(secret string) securityState950 {
	s.mu.Lock()
	defer s.mu.Unlock()
	mfa := map[string]mfaPersistRecord950{}
	if s.persistent == nil {
		mfa = make(map[string]mfaPersistRecord950, len(s.mfa))
		for userID, rec := range s.mfa {
			mfa[userID] = mfaPersistRecord950{PendingSecretEncrypted: encryptString950(secret, rec.PendingSecret), ActiveSecretEncrypted: encryptString950(secret, rec.ActiveSecret), Enabled: rec.Enabled, Recovery: copyMap950(rec.Recovery), UpdatedAt: rec.UpdatedAt}
		}
	}
	return securityState950{MFA: mfa, FailedLogins: copyMap950(s.failedLogins), PasswordResets: copyMap950(s.passwordResets), EmailTokens: copyMap950(s.emailTokens), EmailVerified: copyMap950(s.emailVerified), RecoveryUseLog: append([]map[string]any(nil), s.recoveryUseLog...)}
}

func (s *securityHardeningStore) import950(state securityState950, secret string) error {
	if s.persistent != nil && len(state.MFA) > 0 {
		if err := s.persistent.importLegacyMFA(state); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistent == nil && len(state.MFA) > 0 {
		converted := make(map[string]mfaRecord, len(state.MFA))
		for userID, rec := range state.MFA {
			converted[userID] = mfaRecord{PendingSecret: decryptString950(secret, rec.PendingSecretEncrypted), ActiveSecret: decryptString950(secret, rec.ActiveSecretEncrypted), Enabled: rec.Enabled, Recovery: copyMap950(rec.Recovery), UpdatedAt: rec.UpdatedAt}
		}
		s.mfa = converted
	}
	if len(state.FailedLogins) > 0 {
		s.failedLogins = state.FailedLogins
	}
	if len(state.PasswordResets) > 0 {
		s.passwordResets = state.PasswordResets
	}
	if len(state.EmailTokens) > 0 {
		s.emailTokens = state.EmailTokens
	}
	if len(state.EmailVerified) > 0 {
		s.emailVerified = state.EmailVerified
	}
	if len(state.RecoveryUseLog) > 0 {
		s.recoveryUseLog = state.RecoveryUseLog
	}
	return nil
}

func (b *serverBridgeStore) export950() serverBridgeState950 {
	if b.backendV2() != nil {
		return serverBridgeState950{Servers: map[string]bridgeServerRecord{}, Joins: map[string]bridgeJoinRecord{}, Textures: map[string]bridgeTextureRecord{}}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return serverBridgeState950{Servers: copyMap950(b.servers), Joins: copyMap950(b.joins), Textures: copyMap950(b.textures)}
}

func (b *serverBridgeStore) import950(state serverBridgeState950) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.servers == nil {
		b.servers = map[string]bridgeServerRecord{}
	}
	if b.joins == nil {
		b.joins = map[string]bridgeJoinRecord{}
	}
	if b.textures == nil {
		b.textures = map[string]bridgeTextureRecord{}
	}
	for k, v := range state.Servers {
		b.servers[k] = v
	}
	for k, v := range state.Joins {
		b.joins[k] = v
	}
	for k, v := range state.Textures {
		b.textures[k] = v
	}
}

func encryptString950(secret, plaintext string) string {
	if plaintext == "" {
		return ""
	}
	key := sha256.Sum256([]byte(firstNonEmpty(secret, "dev-only-change-me")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(persistenceSchema950))
	return base64.RawURLEncoding.EncodeToString(sealed)
}

func decryptString950(secret, ciphertext string) string {
	if ciphertext == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return ""
	}
	key := sha256.Sum256([]byte(firstNonEmpty(secret, "dev-only-change-me")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return ""
	}
	nonce := raw[:gcm.NonceSize()]
	payload := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, payload, []byte(persistenceSchema950))
	if err != nil {
		return ""
	}
	return string(plain)
}

func copyMap950[K comparable, V any](src map[K]V) map[K]V {
	dst := make(map[K]V, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func isMemoryRepository950(driver string) bool {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "memory", "inmemory", "in-memory":
		return true
	default:
		return false
	}
}

func isProduction950(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "prod", "production", "e2e-production":
		return true
	default:
		return false
	}
}

func boolStatus950(ok bool) string {
	if ok {
		return "ok"
	}
	return "failed"
}

func redactDSN950(dsn string) string {
	if dsn == "" {
		return ""
	}
	at := strings.LastIndex(dsn, "@")
	if at > 0 {
		prefix := dsn[:at]
		if scheme := strings.Index(prefix, "://"); scheme >= 0 {
			return prefix[:scheme+3] + "***:***" + dsn[at:]
		}
	}
	return "redacted"
}
