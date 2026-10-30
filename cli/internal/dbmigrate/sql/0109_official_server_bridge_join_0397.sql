-- NeverLauncher 0.39.7: verified official identity is not a local Yggdrasil session.
-- Existing tickets remain local; a profile proof is generated only by Backend.
ALTER TABLE server_bridge_join_tickets_v2
    ADD COLUMN IF NOT EXISTS identity_realm TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS official_proof TEXT NOT NULL DEFAULT '';
ALTER TABLE server_bridge_join_tickets_v2
    ADD CONSTRAINT server_bridge_identity_realm_0397 CHECK (
        (identity_realm='local' AND official_proof='') OR
        (identity_realm='official' AND minecraft_session_id IS NULL AND length(official_proof) BETWEEN 16 AND 16384)
    );

-- Preserve the original, independently verified official identity through
-- a one-time proxy to backend transfer. Neither column holds a bearer token.
ALTER TABLE server_bridge_handoffs_v2
    ADD COLUMN IF NOT EXISTS identity_realm TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS official_proof TEXT NOT NULL DEFAULT '';
ALTER TABLE server_bridge_handoffs_v2
    ADD CONSTRAINT server_bridge_handoff_identity_realm_0397 CHECK (
        (identity_realm='local' AND official_proof='') OR
        (identity_realm='official' AND minecraft_session_id IS NULL AND length(official_proof) BETWEEN 16 AND 16384)
    );

-- A signed proxy's successful online-mode validation is persisted with the
-- consumed ticket, then carried only through verified one-time handoffs.
ALTER TABLE server_bridge_join_tickets_v2
    ADD COLUMN IF NOT EXISTS online_mode_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE server_bridge_handoffs_v2
    ADD COLUMN IF NOT EXISTS source_online_mode_verified BOOLEAN NOT NULL DEFAULT FALSE;
