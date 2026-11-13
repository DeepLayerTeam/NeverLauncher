-- Repair the reserved CURRENT_ROLE identifier without changing applied migration 0082.
CREATE OR REPLACE FUNCTION nl_session_admission_0297()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_user_role text;
DECLARE v_user_status text;
BEGIN
    IF NEW.status <> 'active' THEN RETURN NEW; END IF;
    SELECT role_id,status INTO v_user_role,v_user_status FROM users WHERE id=NEW.user_id FOR SHARE;
    IF NOT FOUND OR v_user_status IS DISTINCT FROM 'active' OR NEW.role_id IS DISTINCT FROM v_user_role THEN
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
