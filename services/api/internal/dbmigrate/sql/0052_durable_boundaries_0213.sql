-- NeverLauncher 0.21.3 — durable control-plane boundaries.
-- Publish work, distributed mutation leases, outbox delivery, idempotency and
-- one-time nonces are PostgreSQL state and survive API process restart.

CREATE TABLE IF NOT EXISTS durable_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_token TEXT NOT NULL DEFAULT '',
    lease_fence BIGINT NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 8,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT NOT NULL DEFAULT '',
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT durable_jobs_status_0213 CHECK (status IN ('pending','running','succeeded','failed','revoked','dead')),
    CONSTRAINT durable_jobs_payload_digest_0213 CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT durable_jobs_attempts_0213 CHECK (attempt_count >= 0 AND max_attempts > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_durable_jobs_idempotency_0213 ON durable_jobs(kind,actor_type,actor_id,idempotency_key);
CREATE INDEX IF NOT EXISTS idx_durable_jobs_claim_0213 ON durable_jobs(kind,status,available_at,created_at);
CREATE INDEX IF NOT EXISTS idx_durable_jobs_expired_lease_0213 ON durable_jobs(status,lease_expires_at) WHERE status='running';

CREATE TABLE IF NOT EXISTS durable_job_attempts (
    id BIGSERIAL PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES durable_jobs(id) ON DELETE CASCADE,
    attempt INTEGER NOT NULL,
    worker_id TEXT NOT NULL,
    lease_fence BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT NOT NULL DEFAULT '',
    UNIQUE(job_id,attempt),
    CONSTRAINT durable_job_attempt_status_0213 CHECK (status IN ('running','succeeded','failed','revoked','dead'))
);

CREATE TABLE IF NOT EXISTS durable_scope_leases (
    scope_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    lease_token TEXT NOT NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT durable_scope_fence_0213 CHECK (fencing_token > 0)
);
CREATE INDEX IF NOT EXISTS idx_durable_scope_expiry_0213 ON durable_scope_leases(expires_at);

CREATE TABLE IF NOT EXISTS event_outbox (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT '',
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_token TEXT NOT NULL DEFAULT '',
    lease_fence BIGINT NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 12,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    CONSTRAINT event_outbox_status_0213 CHECK (status IN ('pending','running','delivered','dead')),
    CONSTRAINT event_outbox_attempts_0213 CHECK (attempt_count >= 0 AND max_attempts > 0)
);
CREATE INDEX IF NOT EXISTS idx_event_outbox_claim_0213 ON event_outbox(status,available_at,created_at);
CREATE INDEX IF NOT EXISTS idx_event_outbox_expired_lease_0213 ON event_outbox(status,lease_expires_at) WHERE status='running';

CREATE TABLE IF NOT EXISTS used_nonces (
    namespace TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    subject_id TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(namespace,nonce_hash),
    CONSTRAINT used_nonce_hash_0213 CHECK (nonce_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_used_nonces_expiry_0213 ON used_nonces(expires_at);

CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'in-progress',
    response JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(scope,idempotency_key),
    CONSTRAINT idempotency_digest_0213 CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT idempotency_status_0213 CHECK (status IN ('in-progress','completed','failed'))
);
CREATE INDEX IF NOT EXISTS idx_idempotency_expiry_0213 ON idempotency_records(expires_at);

-- A crashed worker must not keep work permanently running. Recovery is safe
-- because publication is fenced/CAS-protected and the job is idempotent.
UPDATE durable_jobs
SET status='pending', lease_owner='', lease_token='', lease_expires_at=NULL,
    available_at=now(), updated_at=now(), last_error='recovered expired lease'
WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= now();

UPDATE event_outbox
SET status='pending', lease_owner='', lease_token='', lease_expires_at=NULL,
    available_at=now(), updated_at=now(), last_error='recovered expired lease'
WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= now();
