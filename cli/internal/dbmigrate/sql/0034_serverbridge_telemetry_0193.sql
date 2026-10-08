-- NeverLauncher 0.19.3: ограниченный ServerBridge v3 телеметрия история.
ALTER TABLE server_bridge_nodes_v2
    ADD COLUMN IF NOT EXISTS telemetry_latest JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS telemetry_sampled_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS server_bridge_telemetry_samples_v3 (
    sample_id BIGSERIAL PRIMARY KEY,
    server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    runtime_epoch BIGINT NOT NULL CHECK (runtime_epoch > 0),
    runtime_id TEXT NOT NULL CHECK (runtime_id ~ '^[0-9a-f]{64}$'),
    sample_sequence BIGINT NOT NULL CHECK (sample_sequence > 0),
    sampled_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    UNIQUE(server_id, runtime_epoch, sampled_at, sample_sequence)
);

CREATE INDEX IF NOT EXISTS idx_server_bridge_telemetry_server_sampled
    ON server_bridge_telemetry_samples_v3(server_id, sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_server_bridge_telemetry_sampled
    ON server_bridge_telemetry_samples_v3(sampled_at);
