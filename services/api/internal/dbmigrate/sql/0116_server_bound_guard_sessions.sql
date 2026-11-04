-- 0.50.7: non-secret, durable player/Guard/build binding. Only a successfully
-- verified Guard v2 + signed component plan can create these records.
-- Do not reference ephemeral join tickets with ON DELETE CASCADE: the ticket
-- can be pruned while the correlated player is still connected.
CREATE TABLE IF NOT EXISTS server_bridge_guard_sessions_0507 (
    correlation_id CHAR(64) PRIMARY KEY CHECK (correlation_id ~ '^[0-9a-f]{64}$'),
    join_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    minecraft_session_id TEXT NOT NULL DEFAULT '',
    trusted_device_id TEXT NOT NULL,
    device_key_fingerprint CHAR(64) NOT NULL,
    binding_epoch BIGINT NOT NULL CHECK (binding_epoch > 0),
    server_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    username TEXT NOT NULL,
    player_uuid TEXT NOT NULL,
    identity_realm TEXT NOT NULL CHECK (identity_realm IN ('local','official')),
    plan_sha256 CHAR(64) NOT NULL,
    catalog_sha256 CHAR(64) NOT NULL,
    release_signature CHAR(128) NOT NULL,
    guard_attestation_sha256 CHAR(64) NOT NULL,
    guard_evidence_sha256 CHAR(64) NOT NULL,
    guard_sha256 CHAR(64) NOT NULL,
    launcher_sha256 CHAR(64) NOT NULL,
    launcher_version TEXT NOT NULL,
    runtime_policy_sha256 CHAR(64) NOT NULL,
    module_set_sha256 CHAR(64) NOT NULL,
    code_set_sha256 CHAR(64) NOT NULL,
    hook_set_sha256 CHAR(64) NOT NULL,
    jvm_state_sha256 CHAR(64) NOT NULL,
    java_major INTEGER NOT NULL CHECK (java_major > 0),
    guard_pid BIGINT NOT NULL CHECK (guard_pid > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    last_checked_at TIMESTAMPTZ,
    CHECK (length(user_id)>0 AND length(session_id)>0 AND length(server_id)>0)
);
CREATE INDEX IF NOT EXISTS idx_bridge_guard_sessions_due_0507 ON server_bridge_guard_sessions_0507(last_checked_at, correlation_id);
CREATE INDEX IF NOT EXISTS idx_bridge_guard_sessions_auth_0507 ON server_bridge_guard_sessions_0507(session_id, user_id);

-- Upgrade the existing database-side revoke trigger, not the historical 0082
-- migration. PostgreSQL global auth/session cascade must never enqueue a
-- username-only kick that could disconnect a different, newer session.
-- The existing nl_player_revoke_kick_0297 trigger points at this function.
CREATE OR REPLACE FUNCTION nl_queue_revoked_player_kicks_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    node RECORD;
    kick_reason text := 'Launcher session invalidated';
    actor text := 'serverbridge-player-session';
    payload_text text;
    payload_hash text;
    key_hash text;
    command_id text;
    key_id text;
    request_hash text;
    stamp timestamptz := coalesce(NEW.invalidated_at, now());
BEGIN
    IF OLD.status <> 'active' OR NEW.status <> 'invalidated' THEN
        RETURN NEW;
    END IF;
    IF nullif(btrim(NEW.invalidated_reason), '') IS NOT NULL THEN
        kick_reason := kick_reason || ': ' || btrim(NEW.invalidated_reason);
    END IF;
    -- Correlation MUST be in the payload: a newer login may reuse the same
    -- username before the previous queued command is consumed. The JSON
    -- key order matches the canonical Go json.Marshal map order used by
    -- queuePlayerKickTx0197, so payload/request digests and command IDs agree.
    payload_text := '{"reason":' || to_json(kick_reason)::text ||
        ',"sessionCorrelationId":' || to_json(NEW.correlation_id::text)::text ||
        ',"username":' || to_json(OLD.username)::text || '}';
    payload_hash := encode(sha256(convert_to(payload_text, 'UTF8')), 'hex');
    FOR node IN SELECT * FROM (VALUES
       (OLD.proxy_node_id, OLD.proxy_runtime_id, OLD.proxy_runtime_epoch),
       (OLD.backend_node_id, OLD.backend_runtime_id, OLD.backend_runtime_epoch)
    ) AS n(server_id,runtime_id,runtime_epoch)
    LOOP
        IF node.server_id IS NULL OR node.runtime_epoch < 1 OR
           node.runtime_id !~ '^[0-9a-f]{64}$' THEN
            CONTINUE;
        END IF;
        key_hash := encode(sha256(convert_to(
            NEW.correlation_id || E'\n' || node.server_id || E'\n' || node.runtime_id ||
            E'\n' || node.runtime_epoch::text || E'\n' || kick_reason, 'UTF8')), 'hex');
        command_id := 'ctlps_' || left(key_hash,48);
        key_id := 'player-session-' || left(key_hash,40);
        request_hash := encode(sha256(convert_to(node.server_id || E'\n' ||
            node.runtime_epoch::text || E'\n' || node.runtime_id ||
            E'\nplayer.kick' || E'\n' || payload_hash || E'\n' || actor ||
            E'\n' || key_id, 'UTF8')), 'hex');
        INSERT INTO server_bridge_control_commands_v3(
            id,server_id,runtime_epoch,runtime_id,command_type,payload,
            payload_sha256,request_digest,requested_by,idempotency_key,
            status,attempt,created_at,updated_at,expires_at,result,error)
        VALUES(command_id,node.server_id,node.runtime_epoch,node.runtime_id,
            'player.kick',payload_text::jsonb,payload_hash,request_hash,actor,
            key_id,'pending',0,stamp,stamp,stamp + interval '2 minutes','{}'::jsonb,'')
        ON CONFLICT(server_id,requested_by,idempotency_key) DO NOTHING;
    END LOOP;
    RETURN NEW;
END;
$$;
