package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// sqliteRuntimeBackend0373 binds HTTP-only stores to the same WAL database and
// exclusive ownership as the application's primary repository.
type sqliteRuntimeBackend0373 interface {
	ReadRuntimeComponent0373(context.Context, string) ([]byte, bool, error)
	WriteRuntimeComponent0373(context.Context, string, []byte) error
}

// All existing memory-store operations protect their data with mu. Persisting
// under that lock ensures a consumed recovery code/refresh token/Bridge nonce
// cannot be used by another request before the commit has completed.
// An I/O failure poisons the component and aborts the active operation rather
// than returning an authentication success based only on volatile state.
type sqliteRuntimeMutex0373 struct {
	mu       sync.Mutex
	onUnlock func() error
	poisoned error
}

func (m *sqliteRuntimeMutex0373) Lock() {
	m.mu.Lock()
	if m.poisoned != nil {
		e := m.poisoned
		m.mu.Unlock()
		panic(fmt.Errorf("SQLite runtime unavailable: %w", e))
	}
}
func (m *sqliteRuntimeMutex0373) Unlock() {
	defer m.mu.Unlock()
	if m.onUnlock != nil {
		if err := m.onUnlock(); err != nil {
			m.poisoned = err
			panic(fmt.Errorf("SQLite runtime commit failed (operation must not succeed): %w", err))
		}
	}
}

// JSON envelopes explicitly preserve secret/hash fields intentionally omitted
// from public API JSON. The entire envelope is encrypted before reaching WAL.
type sqliteSessionRecord0373 struct {
	Record      authSessionRecord `json:"record"`
	RefreshHash string            `json:"refreshHash"`
}
type sqliteSessions0373 struct {
	Version  int                                `json:"version"`
	Sessions map[string]sqliteSessionRecord0373 `json:"sessions"`
	Tokens   map[string]refreshTokenRecord111   `json:"tokens"`
	Families map[string]refreshFamilyRecord111  `json:"families"`
}
type sqliteMFA0373 struct {
	Pending   string            `json:"pending"`
	Active    string            `json:"active"`
	Enabled   bool              `json:"enabled"`
	Recovery  map[string]string `json:"recovery"`
	UpdatedAt time.Time         `json:"updatedAt"`
}
type sqliteToken0373 struct {
	Record oneTimeSecurityToken `json:"record"`
	Hash   string               `json:"hash"`
}
type sqliteSecurity0373 struct {
	Version       int                           `json:"version"`
	MFA           map[string]sqliteMFA0373      `json:"mfa"`
	Failures      map[string]loginFailureRecord `json:"failures"`
	Resets        map[string]sqliteToken0373    `json:"resets"`
	EmailTokens   map[string]sqliteToken0373    `json:"emailTokens"`
	EmailVerified map[string]bool               `json:"emailVerified"`
	RecoveryLog   []map[string]any              `json:"recoveryLog"`
}
type sqliteCredential0373 struct {
	Record        passkeyCredential117 `json:"record"`
	CredentialID  []byte               `json:"credentialId"`
	UserHandle    []byte               `json:"userHandle"`
	PublicKeyCOSE []byte               `json:"publicKeyCose"`
	AAGUID        []byte               `json:"aaguid"`
}
type sqlitePasskeys0373 struct {
	Version     int                             `json:"version"`
	Credentials map[string]sqliteCredential0373 `json:"credentials"`
	Challenges  map[string]webauthnChallenge117 `json:"challenges"`
	Policies    map[string]string               `json:"policies"`
}
type sqliteServer0373 struct {
	Record      bridgeServerRecord `json:"record"`
	TokenHash   string             `json:"tokenHash"`
	TokenPrefix string             `json:"tokenPrefix"`
	PublicKey   string             `json:"publicKey"`
}
type sqliteJoin0373 struct {
	Record          bridgeJoinRecord `json:"record"`
	AccessTokenHash string           `json:"accessTokenHash"`
}
type sqliteBridge0373 struct {
	Version      int                                          `json:"version"`
	Servers      map[string]sqliteServer0373                  `json:"servers"`
	Joins        map[string]sqliteJoin0373                    `json:"joins"`
	Textures     map[string]bridgeTextureRecord               `json:"textures"`
	Nonces       map[string]time.Time                         `json:"nonces"`
	EventAck     map[string]int64                             `json:"eventAck"`
	EventDigests map[string]string                            `json:"eventDigests"`
	EventIDs     map[string]string                            `json:"eventIds"`
	Commands     map[string]model.ServerBridgeControlCommand  `json:"commands"`
	Routing      map[string]model.ServerBridgeRoutingSnapshot `json:"routing"`
	Idempotency  map[string]string                            `json:"idempotency"`
	Sequence     int64                                        `json:"sequence"`
}

// ConfigureSQLiteRuntime0373 restores all supported state BEFORE the HTTP
// listener is started. It refuses to silently reinitialize unreadable stores.
// The secret must remain stable over restarts and must be backed up securely.
func ConfigureSQLiteRuntime0373(ctx context.Context, state *RuntimeState, backend any, secret string) error {
	if state == nil || state.AuthSessions == nil || state.Security == nil || state.Passkeys == nil || state.ServerBridge == nil {
		return errors.New("SQLite runtime state missing")
	}
	store, ok := backend.(sqliteRuntimeBackend0373)
	if !ok {
		return errors.New("SQLite runtime requires SQLite HTTP repository")
	}
	if len(secret) < 32 {
		return errors.New("SQLite runtime requires at least 32 bytes of stable NEVERLAUNCHER_AUTH_TOKEN_SECRET")
	}
	// Load everything before binding mutation hooks. This rejects wrong keys,
	// corrupt ciphertext and incompatible component formats at startup.
	var sessions sqliteSessions0373
	if err := sqliteRead0373(ctx, store, "sessions", secret, &sessions); err != nil {
		return err
	}
	if sessions.Version != 0 && sessions.Version != 1 {
		return fmt.Errorf("unsupported SQLite sessions format %d", sessions.Version)
	}
	if sessions.Version != 0 {
		for id, item := range sessions.Sessions {
			item.Record.RefreshHash = item.RefreshHash
			state.AuthSessions.sessions[id] = item.Record
		}
		state.AuthSessions.tokens = sessions.Tokens
		for id, rec := range state.AuthSessions.sessions {
			if rec.Status == "active" {
				if rec.RefreshHash == "" || rec.RefreshFamily == "" {
					return fmt.Errorf("SQLite active session %s missing refresh binding", id)
				}
				if _, ok := sessions.Tokens[rec.RefreshHash]; !ok {
					return fmt.Errorf("SQLite session %s missing refresh token", id)
				}
			}
		}
		state.AuthSessions.families = sessions.Families
	}
	var security sqliteSecurity0373
	if err := sqliteRead0373(ctx, store, "security", secret, &security); err != nil {
		return err
	}
	if security.Version != 0 && security.Version != 1 {
		return fmt.Errorf("unsupported SQLite security format %d", security.Version)
	}
	if security.Version != 0 {
		state.Security.mfa = make(map[string]mfaRecord, len(security.MFA))
		for id, v := range security.MFA {
			state.Security.mfa[id] = mfaRecord{PendingSecret: v.Pending, ActiveSecret: v.Active, Enabled: v.Enabled, Recovery: v.Recovery, UpdatedAt: v.UpdatedAt}
		}
		state.Security.failedLogins = security.Failures
		state.Security.passwordResets = make(map[string]oneTimeSecurityToken, len(security.Resets))
		for k, v := range security.Resets {
			v.Record.TokenHash = v.Hash
			if k != v.Hash {
				return fmt.Errorf("SQLite reset token hash mismatch")
			}
			state.Security.passwordResets[k] = v.Record
		}
		state.Security.emailTokens = make(map[string]oneTimeSecurityToken, len(security.EmailTokens))
		for k, v := range security.EmailTokens {
			v.Record.TokenHash = v.Hash
			if k != v.Hash {
				return fmt.Errorf("SQLite email token hash mismatch")
			}
			state.Security.emailTokens[k] = v.Record
		}
		state.Security.emailVerified = security.EmailVerified
		state.Security.recoveryUseLog = security.RecoveryLog
	}
	var passkeys sqlitePasskeys0373
	if err := sqliteRead0373(ctx, store, "passkeys", secret, &passkeys); err != nil {
		return err
	}
	if passkeys.Version != 0 && passkeys.Version != 1 {
		return fmt.Errorf("unsupported SQLite passkeys format %d", passkeys.Version)
	}
	if passkeys.Version != 0 {
		state.Passkeys.credentials = make(map[string]passkeyCredential117, len(passkeys.Credentials))
		state.Passkeys.credentialIndex = make(map[string]string, len(passkeys.Credentials))
		for id, v := range passkeys.Credentials {
			rec := v.Record
			rec.CredentialID = v.CredentialID
			rec.UserHandle = v.UserHandle
			rec.PublicKeyCOSE = v.PublicKeyCOSE
			rec.AAGUID = v.AAGUID
			index := base64.RawURLEncoding.EncodeToString(v.CredentialID)
			if len(v.CredentialID) == 0 || rec.ID != id {
				return fmt.Errorf("invalid SQLite passkey credential %q", id)
			}
			if _, duplicate := state.Passkeys.credentialIndex[index]; duplicate {
				return errors.New("duplicate SQLite credential identifier")
			}
			state.Passkeys.credentials[id] = rec
			state.Passkeys.credentialIndex[index] = id
		}
		state.Passkeys.challenges = passkeys.Challenges
		state.Passkeys.policies = passkeys.Policies
	}
	var bridge sqliteBridge0373
	if err := sqliteRead0373(ctx, store, "bridge", secret, &bridge); err != nil {
		return err
	}
	if bridge.Version != 0 && bridge.Version != 1 {
		return fmt.Errorf("unsupported SQLite bridge format %d", bridge.Version)
	}
	if bridge.Version != 0 {
		state.ServerBridge.servers = make(map[string]bridgeServerRecord, len(bridge.Servers))
		for id, v := range bridge.Servers {
			v.Record.TokenHash = v.TokenHash
			v.Record.TokenPrefix = v.TokenPrefix
			v.Record.PublicKey = v.PublicKey
			state.ServerBridge.servers[id] = v.Record
		}
		state.ServerBridge.joins = make(map[string]bridgeJoinRecord, len(bridge.Joins))
		for id, v := range bridge.Joins {
			v.Record.AccessTokenHash = v.AccessTokenHash
			state.ServerBridge.joins[id] = v.Record
		}
		state.ServerBridge.textures = bridge.Textures
		state.ServerBridge.nodeNonces = bridge.Nonces
		state.ServerBridge.eventAck = bridge.EventAck
		state.ServerBridge.eventDigests = bridge.EventDigests
		state.ServerBridge.eventIDs = bridge.EventIDs
		state.ServerBridge.controlCommands = bridge.Commands
		state.ServerBridge.routing = bridge.Routing
		state.ServerBridge.controlIdempotency = bridge.Idempotency
		state.ServerBridge.controlSequence = bridge.Sequence
	}
	// Maps must exist even when an older state omitted an optional category.
	state.AuthSessions.ensureMemoryMapsLocked111()
	if state.Security.mfa == nil {
		state.Security.mfa = map[string]mfaRecord{}
	}
	if state.Security.failedLogins == nil {
		state.Security.failedLogins = map[string]loginFailureRecord{}
	}
	if state.Security.passwordResets == nil {
		state.Security.passwordResets = map[string]oneTimeSecurityToken{}
	}
	if state.Security.emailTokens == nil {
		state.Security.emailTokens = map[string]oneTimeSecurityToken{}
	}
	if state.Security.emailVerified == nil {
		state.Security.emailVerified = map[string]bool{}
	}
	if state.Passkeys.challenges == nil {
		state.Passkeys.challenges = map[string]webauthnChallenge117{}
	}
	if state.Passkeys.credentials == nil {
		state.Passkeys.credentials = map[string]passkeyCredential117{}
	}
	if state.Passkeys.credentialIndex == nil {
		state.Passkeys.credentialIndex = map[string]string{}
	}
	if state.Passkeys.policies == nil {
		state.Passkeys.policies = map[string]string{}
	}
	if state.ServerBridge.servers == nil {
		state.ServerBridge.servers = map[string]bridgeServerRecord{}
	}
	if state.ServerBridge.joins == nil {
		state.ServerBridge.joins = map[string]bridgeJoinRecord{}
	}
	if state.ServerBridge.textures == nil {
		state.ServerBridge.textures = map[string]bridgeTextureRecord{}
	}
	if state.ServerBridge.nodeNonces == nil {
		state.ServerBridge.nodeNonces = map[string]time.Time{}
	}
	if state.ServerBridge.controlCommands == nil {
		state.ServerBridge.controlCommands = map[string]model.ServerBridgeControlCommand{}
	}
	if state.ServerBridge.controlIdempotency == nil {
		state.ServerBridge.controlIdempotency = map[string]string{}
	}
	if state.ServerBridge.routing == nil {
		state.ServerBridge.routing = map[string]model.ServerBridgeRoutingSnapshot{}
	}

	state.AuthSessions.mu.onUnlock = sqliteHook0373(store, "sessions", secret, func() any {
		out := sqliteSessions0373{Version: 1, Sessions: map[string]sqliteSessionRecord0373{}, Tokens: state.AuthSessions.tokens, Families: state.AuthSessions.families}
		for id, r := range state.AuthSessions.sessions {
			out.Sessions[id] = sqliteSessionRecord0373{Record: r, RefreshHash: r.RefreshHash}
		}
		return out
	})
	state.Security.mu.onUnlock = sqliteHook0373(store, "security", secret, func() any {
		out := sqliteSecurity0373{Version: 1, MFA: map[string]sqliteMFA0373{}, Failures: state.Security.failedLogins, Resets: map[string]sqliteToken0373{}, EmailTokens: map[string]sqliteToken0373{}, EmailVerified: state.Security.emailVerified, RecoveryLog: state.Security.recoveryUseLog}
		for id, r := range state.Security.mfa {
			out.MFA[id] = sqliteMFA0373{Pending: r.PendingSecret, Active: r.ActiveSecret, Enabled: r.Enabled, Recovery: r.Recovery, UpdatedAt: r.UpdatedAt}
		}
		for id, r := range state.Security.passwordResets {
			out.Resets[id] = sqliteToken0373{Record: r, Hash: r.TokenHash}
		}
		for id, r := range state.Security.emailTokens {
			out.EmailTokens[id] = sqliteToken0373{Record: r, Hash: r.TokenHash}
		}
		return out
	})
	state.Passkeys.mu.onUnlock = sqliteHook0373(store, "passkeys", secret, func() any {
		out := sqlitePasskeys0373{Version: 1, Credentials: map[string]sqliteCredential0373{}, Challenges: state.Passkeys.challenges, Policies: state.Passkeys.policies}
		for id, r := range state.Passkeys.credentials {
			out.Credentials[id] = sqliteCredential0373{Record: r, CredentialID: r.CredentialID, UserHandle: r.UserHandle, PublicKeyCOSE: r.PublicKeyCOSE, AAGUID: r.AAGUID}
		}
		return out
	})
	state.ServerBridge.mu.onUnlock = sqliteHook0373(store, "bridge", secret, func() any {
		out := sqliteBridge0373{Version: 1, Servers: map[string]sqliteServer0373{}, Joins: map[string]sqliteJoin0373{}, Textures: state.ServerBridge.textures, Nonces: state.ServerBridge.nodeNonces, EventAck: state.ServerBridge.eventAck, EventDigests: state.ServerBridge.eventDigests, EventIDs: state.ServerBridge.eventIDs, Commands: state.ServerBridge.controlCommands, Routing: state.ServerBridge.routing, Idempotency: state.ServerBridge.controlIdempotency, Sequence: state.ServerBridge.controlSequence}
		for id, r := range state.ServerBridge.servers {
			out.Servers[id] = sqliteServer0373{Record: r, TokenHash: r.TokenHash, TokenPrefix: r.TokenPrefix, PublicKey: r.PublicKey}
		}
		for id, r := range state.ServerBridge.joins {
			out.Joins[id] = sqliteJoin0373{Record: r, AccessTokenHash: r.AccessTokenHash}
		}
		return out
	})
	return nil
}

func sqliteHook0373(store sqliteRuntimeBackend0373, name, secret string, snapshot func() any) func() error {
	var last [32]byte
	var initialized bool
	return func() error {
		raw, err := json.Marshal(snapshot())
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		if initialized && digest == last {
			return nil
		}
		encrypted, err := sqliteEncrypt0373(secret, name, raw)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = store.WriteRuntimeComponent0373(ctx, name, encrypted); err != nil {
			return err
		}
		last = digest
		initialized = true
		return nil
	}
}
func sqliteEncrypt0373(secret, name string, plain []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), nonce...)
	return aead.Seal(out, nonce, plain, []byte("neverlauncher-runtime-0.37.3:"+name)), nil
}
func sqliteRead0373(ctx context.Context, store sqliteRuntimeBackend0373, name, secret string, out any) error {
	encrypted, found, err := store.ReadRuntimeComponent0373(ctx, name)
	if err != nil {
		return fmt.Errorf("SQLite component %s: %w", name, err)
	}
	if !found {
		return nil
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(encrypted) < aead.NonceSize() {
		return fmt.Errorf("SQLite component %s ciphertext truncated", name)
	}
	raw, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], []byte("neverlauncher-runtime-0.37.3:"+name))
	if err != nil {
		return fmt.Errorf("SQLite component %s: wrong key or corrupted ciphertext: %w", name, err)
	}
	if err = json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("SQLite component %s decode: %w", name, err)
	}
	return nil
}
