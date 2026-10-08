-- NeverLauncher 0.19.2 — ServerBridge 3 Node Discovery & Runtime Identity.
-- Runtime instances are attested by the registered Ed25519 node key and retained
-- as history so JVM restarts and overlapping replacement processes are observable.

ALTER TABLE server_bridge_nodes_v2
    ADD COLUMN IF NOT EXISTS runtime_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS runtime_previous_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_transition TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_replacement_detected BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS runtime_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS runtime_first_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS runtime_last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS runtime_uptime_seconds BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS runtime_identity_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_identity_signature TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_process_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS hostname TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS node_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS minecraft_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS java_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS java_vendor TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS java_vm_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_platform TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS loader_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS loader_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS server_brand TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_runtime_id_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_runtime_id_check
        CHECK (runtime_id = '' OR runtime_id ~ '^[0-9a-f]{64}$');
ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_runtime_digest_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_runtime_digest_check
        CHECK (runtime_identity_digest = '' OR runtime_identity_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_runtime_epoch_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_runtime_epoch_check CHECK (runtime_epoch >= 0);
ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_runtime_uptime_check;
ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_runtime_uptime_check CHECK (runtime_uptime_seconds >= 0);

CREATE TABLE IF NOT EXISTS server_bridge_runtime_instances_v3 (
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    runtime_epoch BIGINT NOT NULL CHECK (runtime_epoch > 0),
    runtime_id TEXT NOT NULL CHECK (runtime_id ~ '^[0-9a-f]{64}$'),
    identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
    node_key_fingerprint TEXT NOT NULL CHECK (node_key_fingerprint ~ '^[0-9a-f]{64}$'),
    identity_digest TEXT NOT NULL CHECK (identity_digest ~ '^[0-9a-f]{64}$'),
    identity_signature TEXT NOT NULL,
    process_id BIGINT NOT NULL CHECK (process_id > 0),
    started_at TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_uptime_seconds BIGINT NOT NULL DEFAULT 0 CHECK (last_uptime_seconds >= 0),
    ended_at TIMESTAMPTZ,
    transition TEXT NOT NULL CHECK (transition IN ('started','restart','replacement')),
    replacement_detected BOOLEAN NOT NULL DEFAULT FALSE,
    hostname TEXT NOT NULL,
    node_name TEXT NOT NULL,
    minecraft_version TEXT NOT NULL,
    java_version TEXT NOT NULL,
    java_vendor TEXT NOT NULL DEFAULT '',
    java_vm_name TEXT NOT NULL DEFAULT '',
    runtime_platform TEXT NOT NULL,
    loader_name TEXT NOT NULL,
    loader_version TEXT NOT NULL DEFAULT '',
    server_brand TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (server_id, runtime_epoch),
    UNIQUE (server_id, identity_epoch, runtime_id)
);

CREATE INDEX IF NOT EXISTS idx_server_bridge_runtime_instances_v3_last_seen
    ON server_bridge_runtime_instances_v3(server_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_server_bridge_runtime_instances_v3_runtime_id
    ON server_bridge_runtime_instances_v3(runtime_id);

COMMENT ON TABLE server_bridge_runtime_instances_v3 IS
    'Ed25519-attested ServerBridge JVM/runtime history used to detect restarts and overlapping process replacements.';
COMMENT ON COLUMN server_bridge_nodes_v2.runtime_epoch IS
    'Monotonic runtime generation for the node identity. Incremented whenever the attested JVM runtime id changes.';
COMMENT ON COLUMN server_bridge_nodes_v2.runtime_replacement_detected IS
    'True when a new runtime id arrived while the previous runtime was still within the ServerBridge freshness window.';
