package sqlitecore

// Migration 326. No ephemeral authority or implicit success is possible:
// runtime state, command delivery and extension activation live in one WAL DB.
var fullStateDDL = []string{
	`CREATE TABLE bridge_runtime (
 node_id TEXT PRIMARY KEY REFERENCES bridge_nodes(id) ON DELETE RESTRICT,
 runtime_id TEXT NOT NULL CHECK(length(runtime_id)=64), epoch INTEGER NOT NULL CHECK(epoch>0),
 status TEXT NOT NULL CHECK(status IN('active','disabled')),
 last_heartbeat INTEGER NOT NULL, heartbeat_seq INTEGER NOT NULL CHECK(heartbeat_seq>=1),
 delivery_seq INTEGER NOT NULL DEFAULT 0 CHECK(delivery_seq>=0))`,
	`CREATE TABLE bridge_runtime_nonces (
 node_id TEXT NOT NULL REFERENCES bridge_nodes(id) ON DELETE RESTRICT, epoch INTEGER NOT NULL, nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64), committed_at INTEGER NOT NULL,
 PRIMARY KEY(node_id,epoch,nonce_hash)) WITHOUT ROWID`,
	`CREATE TRIGGER bridge_runtime_nonces_no_delete BEFORE DELETE ON bridge_runtime_nonces BEGIN SELECT RAISE(ABORT,'runtime replay tombstone'); END`,
	`CREATE TABLE bridge_commands (
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES bridge_nodes(id) ON DELETE RESTRICT,
 runtime_id TEXT NOT NULL, runtime_epoch INTEGER NOT NULL CHECK(runtime_epoch>0),
 command_type TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
 payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64), request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
 actor TEXT NOT NULL, idempotency_key TEXT NOT NULL, status TEXT NOT NULL
 CHECK(status IN('pending','leased','succeeded','failed','unsupported','indeterminate','expired')),
 attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 1),
 delivery_seq INTEGER NOT NULL DEFAULT 0 CHECK(delivery_seq>=0),
 lease_owner TEXT NOT NULL DEFAULT '',lease_token TEXT NOT NULL DEFAULT '', lease_until INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER NOT NULL DEFAULT 0,
 result TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result)),failure TEXT NOT NULL DEFAULT '',
 UNIQUE(node_id,actor,idempotency_key), CHECK(expires_at>created_at),
 CHECK((status='leased' AND attempt=1 AND length(lease_owner)>0 AND length(lease_token)=64 AND lease_until>0 AND delivery_seq>0) OR status<>'leased'))`,
	`CREATE INDEX bridge_commands_dispatch ON bridge_commands(node_id,status,created_at)`,
	`CREATE TRIGGER bridge_commands_identity BEFORE UPDATE ON bridge_commands WHEN
 NEW.id<>OLD.id OR NEW.node_id<>OLD.node_id OR NEW.runtime_id<>OLD.runtime_id OR NEW.runtime_epoch<>OLD.runtime_epoch
 OR NEW.command_type<>OLD.command_type OR NEW.payload<>OLD.payload OR NEW.payload_digest<>OLD.payload_digest
 OR NEW.request_digest<>OLD.request_digest OR NEW.actor<>OLD.actor OR NEW.idempotency_key<>OLD.idempotency_key
 OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR NEW.attempt<OLD.attempt
 BEGIN SELECT RAISE(ABORT,'immutable bridge command identity'); END`,
	`CREATE TRIGGER bridge_commands_terminal BEFORE UPDATE ON bridge_commands WHEN OLD.status IN('succeeded','failed','unsupported','indeterminate','expired')
 BEGIN SELECT RAISE(ABORT,'terminal bridge command cannot be replayed'); END`,
	`CREATE TRIGGER bridge_commands_no_delete BEFORE DELETE ON bridge_commands BEGIN SELECT RAISE(ABORT,'bridge idempotency tombstone'); END`,
	`CREATE TABLE package_blobs (
 digest TEXT PRIMARY KEY CHECK(length(digest)=64), data BLOB NOT NULL,
 size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 1 AND 16777216), created_at INTEGER NOT NULL,
 CHECK(length(data)=size_bytes))`,
	`CREATE TRIGGER package_blobs_no_change BEFORE UPDATE ON package_blobs BEGIN SELECT RAISE(ABORT,'immutable package bytes'); END`,
	`CREATE TRIGGER package_blobs_no_delete BEFORE DELETE ON package_blobs BEGIN SELECT RAISE(ABORT,'immutable package bytes'); END`,
	`CREATE TABLE extension_publishers (
 id TEXT PRIMARY KEY, public_key BLOB NOT NULL CHECK(length(public_key)=32),
 fingerprint TEXT NOT NULL UNIQUE CHECK(length(fingerprint)=64), active INTEGER NOT NULL CHECK(active IN(0,1)),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
	`CREATE TRIGGER extension_publishers_identity BEFORE UPDATE ON extension_publishers WHEN NEW.id<>OLD.id OR NEW.public_key<>OLD.public_key OR NEW.fingerprint<>OLD.fingerprint
 BEGIN SELECT RAISE(ABORT,'immutable extension publisher identity'); END`,
	`CREATE TABLE extension_packages (
 extension_id TEXT NOT NULL, version TEXT NOT NULL, digest TEXT NOT NULL REFERENCES package_blobs(digest) ON DELETE RESTRICT,
 publisher TEXT NOT NULL REFERENCES extension_publishers(id) ON DELETE RESTRICT, signature BLOB NOT NULL CHECK(length(signature)=64),
 created_at INTEGER NOT NULL, PRIMARY KEY(extension_id,version), UNIQUE(extension_id,version,digest)) WITHOUT ROWID`,
	`CREATE TRIGGER extension_packages_no_update BEFORE UPDATE ON extension_packages BEGIN SELECT RAISE(ABORT,'immutable signed extension version'); END`,
	`CREATE TRIGGER extension_packages_no_delete BEFORE DELETE ON extension_packages BEGIN SELECT RAISE(ABORT,'immutable signed extension version'); END`,
	`CREATE TABLE extension_installs (
 extension_id TEXT NOT NULL, scope TEXT NOT NULL, scope_id TEXT NOT NULL,
 version TEXT NOT NULL DEFAULT '', package_digest TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK(state IN('enabled','disabled','absent','error')),
 generation INTEGER NOT NULL CHECK(generation>0), actor TEXT NOT NULL, updated_at INTEGER NOT NULL,
 PRIMARY KEY(extension_id,scope,scope_id)) WITHOUT ROWID`,
	`CREATE TABLE extension_install_history (
 extension_id TEXT NOT NULL, scope TEXT NOT NULL, scope_id TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0), version TEXT NOT NULL, package_digest TEXT NOT NULL,
 state TEXT NOT NULL, actor TEXT NOT NULL, created_at INTEGER NOT NULL,
 PRIMARY KEY(extension_id,scope,scope_id,generation), FOREIGN KEY(extension_id,scope,scope_id)
 REFERENCES extension_installs(extension_id,scope,scope_id) ON DELETE RESTRICT) WITHOUT ROWID`,
	`CREATE TRIGGER extension_install_history_no_update BEFORE UPDATE ON extension_install_history BEGIN SELECT RAISE(ABORT,'immutable extension history'); END`,
	`CREATE TRIGGER extension_install_history_no_delete BEFORE DELETE ON extension_install_history BEGIN SELECT RAISE(ABORT,'immutable extension history'); END`,
	`CREATE TRIGGER extension_install_generation BEFORE UPDATE ON extension_installs WHEN NEW.generation<>OLD.generation+1 BEGIN SELECT RAISE(ABORT,'extension generation must increase'); END`,
	`CREATE TABLE extension_kv (
 extension_id TEXT NOT NULL, scope TEXT NOT NULL, scope_id TEXT NOT NULL, item_key TEXT NOT NULL,
 value_json TEXT NOT NULL CHECK(json_valid(value_json)), value_digest TEXT NOT NULL CHECK(length(value_digest)=64),
 generation INTEGER NOT NULL CHECK(generation>0), actor TEXT NOT NULL, updated_at INTEGER NOT NULL,
 PRIMARY KEY(extension_id,scope,scope_id,item_key)) WITHOUT ROWID`,
	`CREATE TABLE extension_kv_history (
 extension_id TEXT NOT NULL, scope TEXT NOT NULL, scope_id TEXT NOT NULL, item_key TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0), value_digest TEXT NOT NULL CHECK(length(value_digest)=64),
 actor TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(extension_id,scope,scope_id,item_key,generation),
 FOREIGN KEY(extension_id,scope,scope_id,item_key) REFERENCES extension_kv(extension_id,scope,scope_id,item_key) ON DELETE RESTRICT) WITHOUT ROWID`,
	`CREATE TRIGGER extension_kv_history_no_update BEFORE UPDATE ON extension_kv_history BEGIN SELECT RAISE(ABORT,'immutable extension kv history'); END`,
	`CREATE TRIGGER extension_kv_history_no_delete BEFORE DELETE ON extension_kv_history BEGIN SELECT RAISE(ABORT,'immutable extension kv history'); END`,
	`CREATE TRIGGER extension_kv_generation BEFORE UPDATE ON extension_kv WHEN NEW.generation<>OLD.generation+1 BEGIN SELECT RAISE(ABORT,'extension kv CAS regression'); END`,
}
