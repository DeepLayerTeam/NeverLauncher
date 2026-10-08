-- NeverLauncher 0.19.6: ServerBridge Топология и Маршрутизация 2.
-- Аутентифицировать сигнал состояния публикация подписанный маршрутизация снимок. Передачи являются привязанный
-- к текущий исходник+цель runtime/routing доказательство и отказ с блокировкой на устаревший,
-- обслуживание, draining, unhealthy или полный цели.

ALTER TABLE server_bridge_nodes_v2
    ADD COLUMN IF NOT EXISTS routing_state TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS routing_accepting BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS routing_players_online INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS routing_capacity_max INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS routing_health TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS routing_observed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS routing_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS routing_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS routing_signature TEXT NOT NULL DEFAULT '';

ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_state_check;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_state_check
    CHECK (routing_state IN ('unknown','ready','maintenance','draining'));
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_health_check;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_health_check
    CHECK (routing_health IN ('unknown','healthy','degraded','unhealthy'));
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_capacity_check;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_capacity_check
    CHECK (routing_players_online >= 0 AND routing_capacity_max >= 0 AND routing_revision >= 0);
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_digest_check;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_digest_check
    CHECK (routing_digest = '' OR routing_digest ~ '^[0-9a-f]{64}$');
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_admission_shape_0196;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_admission_shape_0196 CHECK (
    NOT routing_accepting OR (routing_state='ready' AND routing_health IN ('healthy','degraded') AND (routing_capacity_max=0 OR routing_players_online<routing_capacity_max))
);
ALTER TABLE server_bridge_nodes_v2 DROP CONSTRAINT IF EXISTS server_bridge_nodes_routing_proof_shape_0196;
ALTER TABLE server_bridge_nodes_v2 ADD CONSTRAINT server_bridge_nodes_routing_proof_shape_0196 CHECK (
    (routing_revision=0 AND routing_digest='' AND routing_signature='' AND routing_observed_at IS NULL)
    OR
    (routing_revision>0 AND routing_digest ~ '^[0-9a-f]{64}$' AND routing_signature<>'' AND routing_observed_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_server_bridge_nodes_routing_v3
    ON server_bridge_nodes_v2(project_id, profile_id, routing_state, routing_health, routing_accepting, routing_observed_at DESC)
    WHERE status='active';

ALTER TABLE server_bridge_handoffs_v2
    ADD COLUMN IF NOT EXISTS source_runtime_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_runtime_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS source_routing_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS source_routing_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_routing_signature TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_runtime_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_runtime_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS target_routing_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS target_routing_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_routing_signature TEXT NOT NULL DEFAULT '';

ALTER TABLE server_bridge_handoffs_v2 DROP CONSTRAINT IF EXISTS server_bridge_handoff_runtime_ids_check;
ALTER TABLE server_bridge_handoffs_v2 ADD CONSTRAINT server_bridge_handoff_runtime_ids_check CHECK (
    (source_runtime_id='' AND source_runtime_epoch=0 AND target_runtime_id='' AND target_runtime_epoch=0)
    OR
    (source_runtime_id ~ '^[0-9a-f]{64}$' AND source_runtime_epoch>0 AND target_runtime_id ~ '^[0-9a-f]{64}$' AND target_runtime_epoch>0)
);
ALTER TABLE server_bridge_handoffs_v2 DROP CONSTRAINT IF EXISTS server_bridge_handoff_routing_proofs_check;
ALTER TABLE server_bridge_handoffs_v2 ADD CONSTRAINT server_bridge_handoff_routing_proofs_check CHECK (
    (source_routing_digest='' AND source_routing_revision=0 AND target_routing_digest='' AND target_routing_revision=0)
    OR
    (source_routing_digest ~ '^[0-9a-f]{64}$' AND source_routing_revision>0 AND source_routing_signature<>'' AND target_routing_digest ~ '^[0-9a-f]{64}$' AND target_routing_revision>0 AND target_routing_signature<>'')
);

COMMENT ON COLUMN server_bridge_nodes_v2.routing_signature IS
    'Ed25519 node signature over the current runtime-bound routing snapshot.';
COMMENT ON COLUMN server_bridge_handoffs_v2.target_routing_digest IS
    'Target routing proof captured when a v3 handoff is minted; the active target runtime is revalidated at redemption.';
