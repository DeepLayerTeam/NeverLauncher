package sqlitecore

// durableDDL is migration 325. A tombstone for every idempotency key and the
// monotonically increasing lease fence are retained permanently (no TTL GC).
// All mutation SQL is executed under sqlitedurable.Store.Write/BEGIN IMMEDIATE.
var durableDDL = []string{
	`CREATE TABLE durable_jobs (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL,
 action TEXT NOT NULL, project_id TEXT NOT NULL DEFAULT '', resource_type TEXT NOT NULL,
 resource_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
 payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64), status TEXT NOT NULL
 CHECK(status IN('pending','running','succeeded','failed','dead','revoked')),
 lease_owner TEXT NOT NULL DEFAULT '', lease_token TEXT NOT NULL DEFAULT '',
 lease_fence INTEGER NOT NULL DEFAULT 0 CHECK(lease_fence>=0), lease_expires_at INTEGER NOT NULL DEFAULT 0,
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
 max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100), available_at INTEGER NOT NULL,
 last_error TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(result)),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, completed_at INTEGER NOT NULL DEFAULT 0,
 UNIQUE(kind,actor_type,actor_id,idempotency_key),
 CHECK((status='running' AND length(lease_token)=64 AND length(lease_owner)>0 AND lease_expires_at>0)
 OR (status<>'running' AND lease_token='' AND lease_owner='' AND lease_expires_at=0)),
 CHECK((status IN('succeeded','failed','dead','revoked') AND completed_at>0)
 OR (status IN('running','pending') AND completed_at=0)))`,
	`CREATE INDEX durable_jobs_claim ON durable_jobs(status,kind,available_at,created_at,id)`,
	`CREATE INDEX durable_jobs_expired ON durable_jobs(status,lease_expires_at)`,
	`CREATE TRIGGER durable_jobs_identity_immutable BEFORE UPDATE ON durable_jobs
 WHEN NEW.id<>OLD.id OR NEW.kind<>OLD.kind OR NEW.actor_type<>OLD.actor_type OR NEW.actor_id<>OLD.actor_id
 OR NEW.action<>OLD.action OR NEW.project_id<>OLD.project_id OR NEW.resource_type<>OLD.resource_type
 OR NEW.resource_id<>OLD.resource_id OR NEW.idempotency_key<>OLD.idempotency_key
 OR NEW.payload<>OLD.payload OR NEW.payload_digest<>OLD.payload_digest OR NEW.created_at<>OLD.created_at
 BEGIN SELECT RAISE(ABORT,'immutable durable job identity'); END`,
	`CREATE TRIGGER durable_job_terminal_immutable BEFORE UPDATE ON durable_jobs
 WHEN OLD.status IN('succeeded','failed','dead','revoked') BEGIN SELECT RAISE(ABORT,'terminal durable job immutable'); END`,
	`CREATE TRIGGER durable_job_fence_monotonic BEFORE UPDATE ON durable_jobs
 WHEN NEW.lease_fence<OLD.lease_fence OR NEW.attempt_count<OLD.attempt_count
 OR (NEW.lease_token<>OLD.lease_token AND NEW.lease_token<>'' AND NEW.lease_fence<=OLD.lease_fence)
 BEGIN SELECT RAISE(ABORT,'durable job fencing regression'); END`,
	`CREATE TRIGGER durable_jobs_no_delete BEFORE DELETE ON durable_jobs BEGIN SELECT RAISE(ABORT,'durable job idempotency tombstone'); END`,
	`CREATE TABLE durable_job_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES durable_jobs(id) ON DELETE RESTRICT,
 attempt INTEGER NOT NULL CHECK(attempt>0), worker_id TEXT NOT NULL, lease_fence INTEGER NOT NULL CHECK(lease_fence>0),
 started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL CHECK(status IN('running','succeeded','retry','dead','failed','expired')),
 error TEXT NOT NULL DEFAULT '', UNIQUE(job_id,attempt))`,
	`CREATE TRIGGER durable_attempt_identity_immutable BEFORE UPDATE ON durable_job_attempts
 WHEN NEW.job_id<>OLD.job_id OR NEW.attempt<>OLD.attempt OR NEW.worker_id<>OLD.worker_id
 OR NEW.lease_fence<>OLD.lease_fence OR NEW.started_at<>OLD.started_at
 OR OLD.status<>'running' OR NEW.status='running' OR NEW.finished_at<=0
 BEGIN SELECT RAISE(ABORT,'immutable job attempt'); END`,
	`CREATE TRIGGER durable_attempt_no_delete BEFORE DELETE ON durable_job_attempts BEGIN SELECT RAISE(ABORT,'immutable job attempt'); END`,
	`CREATE TABLE durable_scope_leases (
 scope_key TEXT PRIMARY KEY, owner TEXT NOT NULL, lease_token TEXT NOT NULL,
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0), expires_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL)`,
	`CREATE TRIGGER durable_scope_no_delete BEFORE DELETE ON durable_scope_leases BEGIN SELECT RAISE(ABORT,'retain fencing high-water mark'); END`,
	`CREATE TRIGGER durable_scope_fence_monotonic BEFORE UPDATE ON durable_scope_leases
 WHEN NEW.fencing_token<OLD.fencing_token OR (NEW.lease_token<>OLD.lease_token AND NEW.lease_token<>'' AND NEW.fencing_token<=OLD.fencing_token) BEGIN SELECT RAISE(ABORT,'scope fence regression'); END`,
	`CREATE TABLE durable_outbox (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL, project_id TEXT NOT NULL DEFAULT '',
 aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, actor_id TEXT NOT NULL DEFAULT '',
 idempotency_key TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
 payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
 status TEXT NOT NULL CHECK(status IN('pending','running','delivered','dead')),
 lease_owner TEXT NOT NULL DEFAULT '', lease_token TEXT NOT NULL DEFAULT '', lease_fence INTEGER NOT NULL DEFAULT 0 CHECK(lease_fence>=0),
 lease_expires_at INTEGER NOT NULL DEFAULT 0, attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
 max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100), available_at INTEGER NOT NULL,
 last_error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, delivered_at INTEGER NOT NULL DEFAULT 0,
 UNIQUE(event_type,project_id,aggregate_type,aggregate_id,idempotency_key),
 CHECK((status='running' AND length(lease_token)=64 AND length(lease_owner)>0 AND lease_expires_at>0)
 OR (status<>'running' AND lease_token='' AND lease_owner='' AND lease_expires_at=0)),
 CHECK((status='delivered' AND delivered_at>0) OR (status<>'delivered' AND delivered_at=0)))`,
	`CREATE INDEX durable_outbox_claim ON durable_outbox(status,available_at,created_at,id)`,
	`CREATE INDEX durable_outbox_expired ON durable_outbox(status,lease_expires_at)`,
	`CREATE TRIGGER durable_outbox_identity_immutable BEFORE UPDATE ON durable_outbox
 WHEN NEW.id<>OLD.id OR NEW.event_type<>OLD.event_type OR NEW.project_id<>OLD.project_id
 OR NEW.aggregate_type<>OLD.aggregate_type OR NEW.aggregate_id<>OLD.aggregate_id OR NEW.actor_id<>OLD.actor_id
 OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.payload<>OLD.payload
 OR NEW.payload_digest<>OLD.payload_digest OR NEW.created_at<>OLD.created_at
 BEGIN SELECT RAISE(ABORT,'immutable outbox identity'); END`,
	`CREATE TRIGGER durable_outbox_terminal_immutable BEFORE UPDATE ON durable_outbox
 WHEN OLD.status IN('delivered','dead') BEGIN SELECT RAISE(ABORT,'terminal outbox event immutable'); END`,
	`CREATE TRIGGER durable_outbox_fence_monotonic BEFORE UPDATE ON durable_outbox
 WHEN NEW.lease_fence<OLD.lease_fence OR NEW.attempt_count<OLD.attempt_count
 OR (NEW.lease_token<>OLD.lease_token AND NEW.lease_token<>'' AND NEW.lease_fence<=OLD.lease_fence)
 BEGIN SELECT RAISE(ABORT,'outbox fencing regression'); END`,
	`CREATE TRIGGER durable_outbox_no_delete BEFORE DELETE ON durable_outbox BEGIN SELECT RAISE(ABORT,'durable outbox idempotency tombstone'); END`,
}
