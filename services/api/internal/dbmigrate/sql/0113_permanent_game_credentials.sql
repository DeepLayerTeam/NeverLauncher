-- 0.43.4: terminal revocation for device keys and Minecraft credentials.
-- Repair attempts from stale API instances may not reactivate tombstones.
CREATE OR REPLACE FUNCTION nl_device_key_terminal_0434()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='revoked' AND (NEW.status<>'revoked' OR
        OLD.public_key IS DISTINCT FROM NEW.public_key OR
        OLD.key_fingerprint IS DISTINCT FROM NEW.key_fingerprint OR
        OLD.user_id IS DISTINCT FROM NEW.user_id) THEN
        RAISE EXCEPTION 'revoked device key cannot be reactivated or replaced'
            USING ERRCODE='23514';
    END IF;
    IF OLD.public_key IS DISTINCT FROM NEW.public_key OR
        OLD.key_fingerprint IS DISTINCT FROM NEW.key_fingerprint OR
        OLD.key_algorithm IS DISTINCT FROM NEW.key_algorithm OR
        OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'trusted device key is immutable; use rotation/recovery'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_device_key_terminal_0434 ON trusted_devices;
CREATE TRIGGER nl_device_key_terminal_0434
    BEFORE UPDATE ON trusted_devices FOR EACH ROW
    EXECUTE FUNCTION nl_device_key_terminal_0434();

CREATE OR REPLACE FUNCTION nl_minecraft_token_terminal_0434()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='revoked' AND NEW.status<>'revoked' THEN
        RAISE EXCEPTION 'revoked Minecraft credential cannot be reactivated'
            USING ERRCODE='23514';
    END IF;
    IF OLD.access_token_hash IS DISTINCT FROM NEW.access_token_hash OR
        OLD.session_id IS DISTINCT FROM NEW.session_id OR
        OLD.user_id IS DISTINCT FROM NEW.user_id OR
        OLD.profile_uuid IS DISTINCT FROM NEW.profile_uuid OR
        OLD.trusted_device_id IS DISTINCT FROM NEW.trusted_device_id OR
        OLD.binding_epoch IS DISTINCT FROM NEW.binding_epoch THEN
        RAISE EXCEPTION 'Minecraft credential identity and trust binding are immutable'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS nl_minecraft_token_terminal_0434 ON minecraft_sessions;
CREATE TRIGGER nl_minecraft_token_terminal_0434
    BEFORE UPDATE ON minecraft_sessions FOR EACH ROW
    EXECUTE FUNCTION nl_minecraft_token_terminal_0434();
