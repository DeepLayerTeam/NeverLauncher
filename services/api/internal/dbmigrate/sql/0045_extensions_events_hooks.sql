CREATE TABLE IF NOT EXISTS extension_event_log (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    project_id TEXT NOT NULL DEFAULT '',
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    ordering_key TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    source TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT extension_event_log_identity_nonempty CHECK (length(event_id) > 0 AND length(event_type) > 0 AND length(ordering_key) > 0 AND length(idempotency_key) > 0),
    CONSTRAINT extension_event_log_payload_sha256_hex CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE (event_type, idempotency_key)
);

CREATE INDEX IF NOT EXISTS extension_event_log_ordering_idx ON extension_event_log(ordering_key, sequence);
CREATE INDEX IF NOT EXISTS extension_event_log_project_idx ON extension_event_log(project_id, sequence DESC) WHERE project_id <> '';
CREATE INDEX IF NOT EXISTS extension_event_log_type_idx ON extension_event_log(event_type, sequence DESC);

CREATE TABLE IF NOT EXISTS extension_event_subscriptions (
    id BIGSERIAL PRIMARY KEY,
    extension_id TEXT NOT NULL REFERENCES extensions(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK (scope IN ('global','project')),
    scope_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('sync','async')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT extension_event_subscription_scope CHECK ((scope='global' AND scope_id='') OR (scope='project' AND scope_id<>'')),
    UNIQUE(extension_id, scope, scope_id, event_type, mode)
);

CREATE INDEX IF NOT EXISTS extension_event_subscriptions_dispatch_idx ON extension_event_subscriptions(event_type, mode, enabled);
CREATE INDEX IF NOT EXISTS extension_event_subscriptions_extension_idx ON extension_event_subscriptions(extension_id, scope, scope_id);

CREATE TABLE IF NOT EXISTS extension_event_deliveries (
    id BIGSERIAL PRIMARY KEY,
    event_sequence BIGINT NOT NULL REFERENCES extension_event_log(sequence) ON DELETE CASCADE,
    subscription_id BIGINT NOT NULL REFERENCES extension_event_subscriptions(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','retry','delivered','dead')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until TIMESTAMPTZ NULL,
    lease_token TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    delivered_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(event_sequence, subscription_id),
    CONSTRAINT extension_event_delivery_lease_state CHECK ((status='processing' AND lease_until IS NOT NULL AND lease_token<>'') OR (status<>'processing' AND lease_token=''))
);

CREATE INDEX IF NOT EXISTS extension_event_deliveries_ready_idx ON extension_event_deliveries(status, next_attempt_at, id);
CREATE INDEX IF NOT EXISTS extension_event_deliveries_subscription_idx ON extension_event_deliveries(subscription_id, event_sequence);

CREATE TABLE IF NOT EXISTS extension_event_dead_letters (
    id BIGSERIAL PRIMARY KEY,
    delivery_id BIGINT NOT NULL UNIQUE,
    event_sequence BIGINT NOT NULL,
    subscription_id BIGINT NOT NULL,
    extension_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    last_error TEXT NOT NULL,
    event_snapshot JSONB NOT NULL,
    dead_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS extension_event_dead_letters_extension_idx ON extension_event_dead_letters(extension_id, dead_at DESC);
