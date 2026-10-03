-- NeverLauncher 0.19.4: durable ordered ServerBridge v3 event stream.
CREATE TABLE IF NOT EXISTS server_bridge_event_cursors_v3 (
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    runtime_epoch BIGINT NOT NULL CHECK (runtime_epoch > 0),
    runtime_id CHAR(64) NOT NULL CHECK (runtime_id ~ '^[0-9a-f]{64}$'),
    ack_sequence BIGINT NOT NULL DEFAULT 0 CHECK (ack_sequence >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, runtime_epoch)
);

CREATE TABLE IF NOT EXISTS server_bridge_events_v3 (
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    runtime_epoch BIGINT NOT NULL CHECK (runtime_epoch > 0),
    runtime_id CHAR(64) NOT NULL CHECK (runtime_id ~ '^[0-9a-f]{64}$'),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 128),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 96),
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    signature TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, runtime_epoch, sequence),
    UNIQUE (server_id, runtime_epoch, event_id)
);

CREATE INDEX IF NOT EXISTS idx_server_bridge_events_v3_received
    ON server_bridge_events_v3(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_server_bridge_events_v3_type
    ON server_bridge_events_v3(server_id, event_type, occurred_at DESC);
