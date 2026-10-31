package sqlitecore

// These tables extend the existing core schema. They are not a parallel
// in-memory auth store: session validation always consults the same WAL DB as
// users and their monotonically increasing auth_epoch.
var authDDL = []string{
	`CREATE TABLE auth_sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 auth_epoch INTEGER NOT NULL CHECK(auth_epoch>0), device_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 auth_methods TEXT NOT NULL CHECK(json_valid(auth_methods)),
 created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked_at INTEGER NOT NULL DEFAULT 0, revoked_reason TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX auth_sessions_user ON auth_sessions(user_id,status,created_at DESC)`,
	`CREATE TABLE refresh_families (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 status TEXT NOT NULL CHECK(status IN ('active','revoked','compromised')),
 created_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE refresh_tokens (
 token_hash TEXT PRIMARY KEY CHECK(length(token_hash)=64),
 family_id TEXT NOT NULL REFERENCES refresh_families(id) ON DELETE RESTRICT,
 status TEXT NOT NULL CHECK(status IN ('current','consumed','revoked')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE UNIQUE INDEX refresh_one_current ON refresh_tokens(family_id) WHERE status='current'`,
	`CREATE TABLE access_tokens (
 token_hash TEXT PRIMARY KEY CHECK(length(token_hash)=64),
 session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX access_tokens_session ON access_tokens(session_id,revoked_at)`,
	`CREATE TABLE mfa_totp (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 status TEXT NOT NULL CHECK(status IN ('pending','active')),
 secret_ciphertext BLOB NOT NULL, last_step INTEGER NOT NULL DEFAULT -1,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
	`CREATE TABLE mfa_recovery (
 code_hash TEXT PRIMARY KEY CHECK(length(code_hash)=64),
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX mfa_recovery_user ON mfa_recovery(user_id,used_at)`,
	`CREATE TABLE minecraft_profiles (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 uuid TEXT NOT NULL UNIQUE, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
 issuer TEXT NOT NULL, realm TEXT NOT NULL, subject TEXT NOT NULL,
 identity_version TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 CHECK(length(name) BETWEEN 3 AND 16), CHECK(length(uuid)=36))`,
	`CREATE TRIGGER minecraft_uuid_immutable BEFORE UPDATE OF uuid,user_id ON minecraft_profiles
 WHEN NEW.uuid<>OLD.uuid OR NEW.user_id<>OLD.user_id BEGIN SELECT RAISE(ABORT,'minecraft identity immutable'); END`,
	`CREATE TABLE minecraft_sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 profile_uuid TEXT NOT NULL REFERENCES minecraft_profiles(uuid) ON DELETE RESTRICT,
 access_hash TEXT NOT NULL UNIQUE CHECK(length(access_hash)=64),
 status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked_at INTEGER NOT NULL DEFAULT 0, revoked_reason TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX minecraft_sessions ON minecraft_sessions(session_id,status)`,
	`CREATE TABLE auth_revocation_events (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL)`,
	`CREATE TRIGGER revocation_events_no_update BEFORE UPDATE ON auth_revocation_events BEGIN SELECT RAISE(ABORT,'immutable security event'); END`,
	`CREATE TRIGGER revocation_events_no_delete BEFORE DELETE ON auth_revocation_events BEGIN SELECT RAISE(ABORT,'immutable security event'); END`,
}
