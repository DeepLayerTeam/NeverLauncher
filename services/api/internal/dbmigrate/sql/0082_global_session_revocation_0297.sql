-- 0.29.7: single authoritative PostgreSQL transaction for access revocation.
-- Every caller (including device-risk and other API replicas) receives the same
-- cascade. No best-effort post-commit requests or replica-local caches.
CREATE OR REPLACE FUNCTION nl_revoke_session_dependents_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    why text := left(coalesce(nullif(NEW.revoked_reason, ''), 'never-session-revoked'), 512);
    stamp timestamptz := coalesce(NEW.revoked_at, now());
BEGIN
    IF OLD.status <> 'active' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;

    UPDATE refresh_token_families SET status='revoked',revoked_at=coalesce(revoked_at,stamp),
        revoked_reason=why WHERE id=NEW.refresh_family_id AND status='active';
    UPDATE refresh_tokens SET status='revoked',revoked_at=coalesce(revoked_at,stamp)
        WHERE family_id=NEW.refresh_family_id AND status<>'revoked';
    UPDATE minecraft_sessions SET status='revoked',revoked_at=coalesce(revoked_at,stamp),revoked_reason=why
        WHERE never_session_id=NEW.id AND status='active';
    DELETE FROM minecraft_joins WHERE minecraft_session_id IN
        (SELECT id FROM minecraft_sessions WHERE never_session_id=NEW.id);
    UPDATE server_bridge_join_tickets_v2 SET status='invalidated',invalidated_at=stamp
        WHERE session_id=NEW.id AND status='active';
    UPDATE server_bridge_handoffs_v2 SET status='invalidated',invalidated_at=stamp
        WHERE session_id=NEW.id AND status='active';
    UPDATE server_bridge_player_sessions_v3 SET status='invalidated',recheck_required=FALSE,
        invalidated_at=stamp,invalidated_reason=why,updated_at=stamp
        WHERE never_session_id=NEW.id AND status='active';
    UPDATE server_bridge_player_transfers_v3 SET status='invalidated'
        WHERE correlation_id IN
            (SELECT correlation_id FROM server_bridge_player_sessions_v3
             WHERE never_session_id=NEW.id AND status='invalidated')
          AND status='issued';

    INSERT INTO auth_events(user_id,session_id,family_id,event_type,details)
        VALUES(NEW.user_id,NEW.id,NEW.refresh_family_id,'session-cascade-revoked',
               jsonb_build_object('reason',why,'source','postgres-revocation-0297'));

    -- User-authored work loses its lease immediately. Worker commit paths already
    -- require status=running + matching lease token; they cannot publish after this.
    UPDATE durable_job_attempts SET status='revoked',finished_at=stamp,
        error='authorization-revoked' WHERE status='running' AND job_id IN
        (SELECT id FROM durable_jobs WHERE actor_type='user' AND actor_id=NEW.user_id
         AND status IN ('pending','running') AND NOT EXISTS
          (SELECT 1 FROM auth_sessions WHERE user_id=NEW.user_id AND status='active' AND expires_at>stamp));
    UPDATE durable_jobs SET status='revoked',lease_owner='',lease_token='',
        lease_expires_at=NULL,updated_at=stamp,completed_at=stamp,
        last_error='authorization-revoked' WHERE actor_type='user'
        AND actor_id=NEW.user_id AND status IN ('pending','running') AND NOT EXISTS
        (SELECT 1 FROM auth_sessions WHERE user_id=NEW.user_id AND status='active' AND expires_at>stamp);
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_session_revocation_0297 ON auth_sessions;
CREATE TRIGGER nl_session_revocation_0297 AFTER UPDATE OF status ON auth_sessions
    FOR EACH ROW WHEN (OLD.status='active' AND NEW.status='revoked')
    EXECUTE FUNCTION nl_revoke_session_dependents_0297();

-- Terminal sessions cannot be resurrected by buggy code or stale workers.
CREATE OR REPLACE FUNCTION nl_never_session_terminal_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'revoked Never session cannot be reactivated' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_never_session_terminal_0297 ON auth_sessions;
CREATE TRIGGER nl_never_session_terminal_0297 BEFORE UPDATE OF status ON auth_sessions
    FOR EACH ROW EXECUTE FUNCTION nl_never_session_terminal_0297();

-- Security-sensitive user changes revoke even tokens cached in other API replicas.
-- Comparison avoids logging out users for harmless profile/last-login updates.
CREATE OR REPLACE FUNCTION nl_user_security_change_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE why text;
BEGIN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
        why := 'password-changed';
    ELSIF OLD.role_id IS DISTINCT FROM NEW.role_id OR
          OLD.project_roles IS DISTINCT FROM NEW.project_roles THEN
        why := 'permissions-changed';
    ELSIF OLD.status IS DISTINCT FROM NEW.status AND NEW.status <> 'active' THEN
        why := 'account-disabled';
    ELSE
        RETURN NEW;
    END IF;
    UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason=why
        WHERE user_id=NEW.id AND status='active';
    -- Account-level permission/password changes also cancel queued jobs when
    -- all sessions had already expired (no session row fires its cascade).
    UPDATE durable_job_attempts SET status='revoked',finished_at=now(),error='authorization-revoked'
        WHERE status='running' AND job_id IN
            (SELECT id FROM durable_jobs WHERE actor_type='user' AND actor_id=NEW.id
             AND status IN ('pending','running'));
    UPDATE durable_jobs SET status='revoked',lease_owner='',lease_token='',
        lease_expires_at=NULL,updated_at=now(),completed_at=now(),last_error='authorization-revoked'
        WHERE actor_type='user' AND actor_id=NEW.id AND status IN ('pending','running');
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_user_security_change_0297 ON users;
CREATE TRIGGER nl_user_security_change_0297 AFTER UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION nl_user_security_change_0297();

-- Catch direct role-binding edits outside SaveUser as well.
CREATE OR REPLACE FUNCTION nl_project_role_revocation_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_user text;
BEGIN
    IF TG_OP='UPDATE' AND OLD.role_id IS NOT DISTINCT FROM NEW.role_id AND
       OLD.user_id=NEW.user_id AND OLD.project_id=NEW.project_id THEN
        RETURN NEW;
    END IF;
    target_user := CASE WHEN TG_OP='DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason='project-role-changed'
        WHERE user_id=target_user AND status='active';
    IF TG_OP='UPDATE' AND OLD.user_id<>NEW.user_id THEN
        UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason='project-role-changed'
            WHERE user_id=OLD.user_id AND status='active';
    END IF;
    -- A project permission change also fences queued work even when another
    -- Never session is still active or all sessions have already expired.
    UPDATE durable_job_attempts SET status='revoked',finished_at=now(),error='authorization-revoked'
        WHERE status='running' AND job_id IN (
            SELECT id FROM durable_jobs WHERE actor_type='user' AND
              actor_id IN (target_user, CASE WHEN TG_OP='UPDATE' THEN OLD.user_id ELSE target_user END)
              AND status IN ('pending','running'));
    UPDATE durable_jobs SET status='revoked',lease_owner='',lease_token='',
        lease_expires_at=NULL,updated_at=now(),completed_at=now(),last_error='authorization-revoked'
        WHERE actor_type='user' AND
          actor_id IN (target_user, CASE WHEN TG_OP='UPDATE' THEN OLD.user_id ELSE target_user END)
          AND status IN ('pending','running');
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_project_role_revocation_0297 ON project_user_roles;
CREATE TRIGGER nl_project_role_revocation_0297 AFTER INSERT OR UPDATE OR DELETE ON project_user_roles
    FOR EACH ROW EXECUTE FUNCTION nl_project_role_revocation_0297();

-- Changing a *role definition* changes rights without touching any users row.
-- Invalidate both users with this global role and users holding the role on
-- individual projects; otherwise cached JWT permissions can outlive an edit.
CREATE OR REPLACE FUNCTION nl_role_permissions_revocation_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.permissions IS NOT DISTINCT FROM NEW.permissions THEN RETURN NEW; END IF;
    UPDATE auth_sessions SET status='revoked',revoked_at=now(),revoked_reason='role-permissions-changed'
        WHERE status='active' AND user_id IN (
            SELECT id FROM users WHERE role_id=NEW.id
            UNION SELECT user_id FROM project_user_roles WHERE role_id=NEW.id
        );
    UPDATE durable_job_attempts SET status='revoked',finished_at=now(),error='authorization-revoked'
        WHERE status='running' AND job_id IN (
            SELECT id FROM durable_jobs WHERE actor_type='user' AND
            actor_id IN (SELECT id FROM users WHERE role_id=NEW.id
                         UNION SELECT user_id FROM project_user_roles WHERE role_id=NEW.id)
            AND status IN ('pending','running')
        );
    UPDATE durable_jobs SET status='revoked',lease_owner='',lease_token='',
        lease_expires_at=NULL,updated_at=now(),completed_at=now(),last_error='authorization-revoked'
        WHERE actor_type='user' AND status IN ('pending','running')
        AND actor_id IN (SELECT id FROM users WHERE role_id=NEW.id
                         UNION SELECT user_id FROM project_user_roles WHERE role_id=NEW.id);
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_role_permissions_revocation_0297 ON roles;
CREATE TRIGGER nl_role_permissions_revocation_0297 AFTER UPDATE OF permissions ON roles
    FOR EACH ROW EXECUTE FUNCTION nl_role_permissions_revocation_0297();

-- Creation and device binding must serialize with password/role and device
-- revocation. Merely running the one-off cascade does not protect against a
-- concurrent insert using stale user/device data after the cascade finishes.
CREATE OR REPLACE FUNCTION nl_session_admission_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_role text;
DECLARE current_status text;
BEGIN
    IF NEW.status <> 'active' THEN RETURN NEW; END IF;
    SELECT role_id,status INTO current_role,current_status FROM users WHERE id=NEW.user_id FOR SHARE;
    IF NOT FOUND OR current_status<>'active' OR NEW.role_id<>current_role THEN
        RAISE EXCEPTION 'invalid user or stale role for Never session' USING ERRCODE='23514';
    END IF;
    IF NEW.trusted_device_id IS NOT NULL AND NEW.trusted_device_id<>'' THEN
        PERFORM 1 FROM trusted_devices WHERE id=NEW.trusted_device_id AND user_id=NEW.user_id
            AND status='active' FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'revoked or foreign trusted device' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_session_admission_0297 ON auth_sessions;
CREATE TRIGGER nl_session_admission_0297
    BEFORE INSERT OR UPDATE OF trusted_device_id,device_trust_state ON auth_sessions
    FOR EACH ROW EXECUTE FUNCTION nl_session_admission_0297();

-- Direct device and risk changes must use the same path as API endpoints.
CREATE OR REPLACE FUNCTION nl_device_revocation_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='active' AND (NEW.status='revoked' OR
       OLD.public_key IS DISTINCT FROM NEW.public_key OR
       OLD.key_fingerprint IS DISTINCT FROM NEW.key_fingerprint OR
       OLD.trust_state IS DISTINCT FROM NEW.trust_state) THEN
        UPDATE auth_sessions SET status='revoked',revoked_at=now(),
            revoked_reason='trusted-device-changed'
            WHERE user_id=NEW.user_id AND trusted_device_id=NEW.id AND status='active';
        UPDATE durable_job_attempts SET status='revoked',finished_at=now(),error='authorization-revoked'
            WHERE status='running' AND job_id IN (
              SELECT id FROM durable_jobs WHERE actor_type='user'
              AND actor_id=NEW.user_id AND status IN ('pending','running'));
        UPDATE durable_jobs SET status='revoked',lease_owner='',lease_token='',
            lease_expires_at=NULL,updated_at=now(),completed_at=now(),last_error='authorization-revoked'
            WHERE actor_type='user' AND actor_id=NEW.user_id
              AND status IN ('pending','running');
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_device_revocation_0297 ON trusted_devices;
CREATE TRIGGER nl_device_revocation_0297 AFTER UPDATE OF status,public_key,key_fingerprint,trust_state ON trusted_devices
    FOR EACH ROW EXECUTE FUNCTION nl_device_revocation_0297();

CREATE OR REPLACE FUNCTION nl_compromised_session_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status='active' AND
       (NEW.risk_state='compromised' OR NEW.risk_action='revoke') THEN
        UPDATE auth_sessions SET status='revoked',revoked_at=now(),
            revoked_reason='risk-compromised'
            WHERE id=NEW.id AND status='active';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_compromised_session_0297 ON auth_sessions;
CREATE TRIGGER nl_compromised_session_0297 AFTER UPDATE OF risk_state,risk_action ON auth_sessions
    FOR EACH ROW WHEN (NEW.status='active') EXECUTE FUNCTION nl_compromised_session_0297();

-- Lock the parent session at every game-credential issuance boundary. Without
-- FOR SHARE a concurrent revocation could finish its cascade before a stale
-- transaction inserts a new active ticket/handoff/player row.
CREATE OR REPLACE FUNCTION nl_game_authorization_gate_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_user text;
DECLARE parent_session text;
BEGIN
    IF NEW.status <> 'active' THEN RETURN NEW; END IF;
    IF TG_TABLE_NAME='minecraft_sessions' THEN
        subject_user := NEW.user_id;
        parent_session := NEW.never_session_id;
    ELSIF TG_TABLE_NAME='server_bridge_player_sessions_v3' THEN
        subject_user := NEW.user_id;
        parent_session := NEW.never_session_id;
    ELSE
        subject_user := NEW.user_id;
        parent_session := NEW.session_id;
    END IF;
    PERFORM 1 FROM auth_sessions WHERE id=parent_session AND user_id=subject_user
        AND status='active' AND expires_at>now() FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Never session revoked or expired for game admission'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_minecraft_admission_0297 ON minecraft_sessions;
CREATE TRIGGER nl_minecraft_admission_0297 BEFORE INSERT OR UPDATE OF status ON minecraft_sessions
    FOR EACH ROW EXECUTE FUNCTION nl_game_authorization_gate_0297();
DROP TRIGGER IF EXISTS nl_bridge_join_admission_0297 ON server_bridge_join_tickets_v2;
CREATE TRIGGER nl_bridge_join_admission_0297 BEFORE INSERT OR UPDATE OF status ON server_bridge_join_tickets_v2
    FOR EACH ROW EXECUTE FUNCTION nl_game_authorization_gate_0297();
DROP TRIGGER IF EXISTS nl_bridge_handoff_admission_0297 ON server_bridge_handoffs_v2;
CREATE TRIGGER nl_bridge_handoff_admission_0297 BEFORE INSERT OR UPDATE OF status ON server_bridge_handoffs_v2
    FOR EACH ROW EXECUTE FUNCTION nl_game_authorization_gate_0297();
DROP TRIGGER IF EXISTS nl_bridge_player_admission_0297 ON server_bridge_player_sessions_v3;
CREATE TRIGGER nl_bridge_player_admission_0297 BEFORE INSERT OR UPDATE OF status ON server_bridge_player_sessions_v3
    FOR EACH ROW EXECUTE FUNCTION nl_game_authorization_gate_0297();


-- Disconnect players that were *already online*, not only reject future joins.
-- The control-plane consumer receives these durable player.kick commands on its
-- next poll on the connected proxy and backend runtime. PostgreSQL 16 provides
-- sha256(bytea), so this does not rely on pgcrypto or an API replica being alive.
CREATE OR REPLACE FUNCTION nl_queue_revoked_player_kicks_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    node RECORD;
    kick_reason text := 'NeverLauncher session invalidated';
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
    payload_text := '{"reason":' || to_json(kick_reason)::text || ',"username":' || to_json(OLD.username)::text || '}';
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
DROP TRIGGER IF EXISTS nl_player_revoke_kick_0297 ON server_bridge_player_sessions_v3;
CREATE TRIGGER nl_player_revoke_kick_0297
    AFTER UPDATE OF status ON server_bridge_player_sessions_v3
    FOR EACH ROW WHEN (OLD.status='active' AND NEW.status='invalidated')
    EXECUTE FUNCTION nl_queue_revoked_player_kicks_0297();

-- Yggdrasil joins and ServerBridge transfers have different parent keys.
CREATE OR REPLACE FUNCTION nl_minecraft_join_gate_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE sid text;
BEGIN
    SELECT never_session_id INTO sid FROM minecraft_sessions
        WHERE id=NEW.minecraft_session_id AND user_id=NEW.user_id AND status='active';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Minecraft session revoked' USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM auth_sessions WHERE id=sid AND user_id=NEW.user_id
        AND status='active' AND expires_at>now() FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Never session revoked for Minecraft join' USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM minecraft_sessions WHERE id=NEW.minecraft_session_id
        AND status='active' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Minecraft session concurrently revoked' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_minecraft_join_gate_0297 ON minecraft_joins;
CREATE TRIGGER nl_minecraft_join_gate_0297 BEFORE INSERT OR UPDATE ON minecraft_joins
    FOR EACH ROW EXECUTE FUNCTION nl_minecraft_join_gate_0297();

CREATE OR REPLACE FUNCTION nl_bridge_transfer_gate_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status='issued' THEN
        PERFORM 1 FROM server_bridge_player_sessions_v3
            WHERE correlation_id=NEW.correlation_id AND status='active' FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'revoked ServerBridge player session cannot issue transfer'
                USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_bridge_transfer_gate_0297 ON server_bridge_player_transfers_v3;
CREATE TRIGGER nl_bridge_transfer_gate_0297 BEFORE INSERT OR UPDATE OF status ON server_bridge_player_transfers_v3
    FOR EACH ROW EXECUTE FUNCTION nl_bridge_transfer_gate_0297();

CREATE INDEX IF NOT EXISTS idx_bridge_handoff_session_revocation_0297
    ON server_bridge_handoffs_v2(session_id) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_bridge_player_never_revocation_0297
    ON server_bridge_player_sessions_v3(never_session_id) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_durable_jobs_user_revocation_0297
    ON durable_jobs(actor_id) WHERE actor_type='user' AND status IN ('pending','running');
