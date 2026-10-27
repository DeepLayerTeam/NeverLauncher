package sqlitecore

// All ticket and replay data lives in the same durable WAL database as auth.
// No Redis, in-memory fallback or detached transaction participates in redemption.
var joinDDL = []string{
	`CREATE TABLE bridge_nodes (
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
 project_id TEXT NOT NULL, profile_id TEXT NOT NULL, channel TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),
 identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=1),
 status TEXT NOT NULL CHECK(status IN('active','disabled')),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(project_id,channel) REFERENCES channels(project_id,id) ON DELETE RESTRICT)`,
	`CREATE TABLE bridge_nonces (
 node_id TEXT NOT NULL REFERENCES bridge_nodes(id) ON DELETE RESTRICT,
 identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=1),
 nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64),
 action TEXT NOT NULL CHECK(action IN('ping','redeem')),
 committed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>committed_at),
 PRIMARY KEY(node_id,identity_epoch,nonce_hash)) WITHOUT ROWID`,
	`CREATE INDEX bridge_nonces_expiry ON bridge_nonces(expires_at)`,
	`CREATE TRIGGER bridge_nonces_no_update BEFORE UPDATE ON bridge_nonces BEGIN SELECT RAISE(ABORT,'immutable replay nonce'); END`,
	`CREATE TABLE bridge_join_tickets (
 token_hash TEXT PRIMARY KEY CHECK(length(token_hash)=64),
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id TEXT NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 minecraft_session_id TEXT NOT NULL REFERENCES minecraft_sessions(id) ON DELETE RESTRICT,
 access_token_hash TEXT NOT NULL CHECK(length(access_token_hash)=64) REFERENCES access_tokens(token_hash) ON DELETE RESTRICT,
 player_uuid TEXT NOT NULL REFERENCES minecraft_profiles(uuid) ON DELETE RESTRICT,
 username TEXT NOT NULL COLLATE NOCASE,
 node_id TEXT NOT NULL REFERENCES bridge_nodes(id) ON DELETE RESTRICT,
 project_id TEXT NOT NULL, profile_id TEXT NOT NULL, channel TEXT NOT NULL,
 issued_identity_epoch INTEGER NOT NULL CHECK(issued_identity_epoch>0),
 issued_fingerprint TEXT NOT NULL CHECK(length(issued_fingerprint)=64),
 status TEXT NOT NULL CHECK(status IN('active','consumed','replaced','invalidated')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 consumed_at INTEGER NOT NULL DEFAULT 0,
 terminal_at INTEGER NOT NULL DEFAULT 0,
 redeemed_nonce_hash TEXT NOT NULL DEFAULT '', redeemed_remote_ip TEXT NOT NULL DEFAULT '',
 CHECK(expires_at>created_at AND expires_at<=created_at+125000000000),
 CHECK((status='active' AND consumed_at=0 AND terminal_at=0) OR
       (status='consumed' AND consumed_at>0 AND terminal_at=consumed_at AND length(redeemed_nonce_hash)=64) OR
       (status IN('replaced','invalidated') AND consumed_at=0 AND terminal_at>0)),
 FOREIGN KEY(project_id,profile_id) REFERENCES profiles(project_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(project_id,channel) REFERENCES channels(project_id,id) ON DELETE RESTRICT)`,
	`CREATE UNIQUE INDEX bridge_one_active_player ON bridge_join_tickets(node_id,username) WHERE status='active'`,
	`CREATE INDEX bridge_join_session ON bridge_join_tickets(session_id,status)`,
	`CREATE INDEX bridge_join_expiry ON bridge_join_tickets(expires_at,status)`,
	`CREATE TRIGGER bridge_consumed_immutable BEFORE UPDATE ON bridge_join_tickets WHEN OLD.status='consumed'
 BEGIN SELECT RAISE(ABORT,'consumed ticket immutable'); END`,
	`CREATE TRIGGER bridge_ticket_no_delete BEFORE DELETE ON bridge_join_tickets WHEN OLD.status='consumed'
 BEGIN SELECT RAISE(ABORT,'consumed ticket cannot be deleted'); END`,
}
