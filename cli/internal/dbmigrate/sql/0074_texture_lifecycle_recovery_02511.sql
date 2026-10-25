-- 0.25.11: Durable GC fencing and short-lived backup/repair pins.
-- Tokens prevent a paused GC worker from finishing a later worker's lease.
ALTER TABLE texture_blobs ADD COLUMN gc_lease_token TEXT;
CREATE INDEX idx_texture_blobs_gc_lease_02511 ON texture_blobs(gc_lease_token)
  WHERE gc_lease_token IS NOT NULL;

CREATE TABLE texture_backup_pins (
  digest TEXT NOT NULL REFERENCES texture_blobs(digest) ON DELETE CASCADE,
  lease_token TEXT NOT NULL CHECK (length(lease_token) = 64 AND lease_token ~ '^[0-9a-f]{64}$'),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (digest, lease_token)
);
CREATE INDEX idx_texture_backup_pins_expires_02511 ON texture_backup_pins(expires_at);
CREATE INDEX idx_texture_backup_pins_token_02511 ON texture_backup_pins(lease_token);
