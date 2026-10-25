-- HWID is a limited, explicitly opted-in risk hint. Never store raw machine IDs,
-- raw hardware serials, IPs or cross-account plaintext fingerprints here.
CREATE TABLE IF NOT EXISTS hwid_risk_observations (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    baseline_digest TEXT NOT NULL CHECK (baseline_digest ~ '^[0-9a-f]{64}$'),
    pending_digest TEXT NOT NULL DEFAULT '' CHECK (pending_digest = '' OR pending_digest ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('recognized','changed')),
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(user_id,device_id),
    FOREIGN KEY(device_id,user_id) REFERENCES trusted_devices(id,user_id) ON DELETE CASCADE
);
CREATE INDEX idx_hwid_risk_expiry_0299 ON hwid_risk_observations(expires_at);
CREATE TABLE IF NOT EXISTS hwid_risk_appeals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    pending_digest TEXT NOT NULL CHECK (pending_digest ~ '^[0-9a-f]{64}$'),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 8 AND 500),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    resolution TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY(device_id,user_id) REFERENCES trusted_devices(id,user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_hwid_one_pending_0299 ON hwid_risk_appeals(user_id,device_id) WHERE status='pending';
CREATE INDEX idx_hwid_appeals_recent_0299 ON hwid_risk_appeals(created_at DESC);
