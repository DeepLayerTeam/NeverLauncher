-- NeverLauncher 0.19.5: durable, idempotent Backend -> Bridge control queue.
CREATE TABLE IF NOT EXISTS server_bridge_control_commands_v3 (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 8 AND 128),
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    runtime_epoch BIGINT NOT NULL CHECK (runtime_epoch > 0),
    runtime_id CHAR(64) NOT NULL CHECK (runtime_id ~ '^[0-9a-f]{64}$'),
    command_type TEXT NOT NULL CHECK (length(command_type) BETWEEN 3 AND 64),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    request_digest CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    requested_by TEXT NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 320),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','succeeded','failed','unsupported','indeterminate','expired')),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT NOT NULL DEFAULT '',
    UNIQUE (server_id, requested_by, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_pending_v3
    ON server_bridge_control_commands_v3(server_id, status, created_at)
    WHERE status IN ('pending','leased');
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_retention_v3
    ON server_bridge_control_commands_v3(updated_at);

-- Existing administrator role gains explicit control permissions. Owner already carries '*'.
UPDATE roles
SET permissions = CASE
    WHEN permissions ? 'serverbridge:control' THEN permissions
    ELSE permissions || '["serverbridge:control"]'::jsonb
END
WHERE id='admin';
UPDATE roles
SET permissions = CASE
    WHEN permissions ? 'serverbridge:console' THEN permissions
    ELSE permissions || '["serverbridge:console"]'::jsonb
END
WHERE id='admin';
