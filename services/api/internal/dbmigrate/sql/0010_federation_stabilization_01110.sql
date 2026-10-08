-- NeverLauncher 0.11.10 — Federation E2E / migration stabilization.
-- Refuse already-corrupt authentication state before adding relational invariants.

DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken FROM auth_sessions WHERE status NOT IN ('active','revoked');
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % auth_sessions rows have invalid status', broken; END IF;

    SELECT count(*) INTO broken FROM refresh_token_families WHERE status NOT IN ('active','revoked','compromised');
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % refresh_token_families rows have invalid status', broken; END IF;

    SELECT count(*) INTO broken FROM refresh_tokens WHERE status NOT IN ('current','consumed','revoked');
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % refresh_tokens rows have invalid status', broken; END IF;

    SELECT count(*) INTO broken
    FROM auth_sessions s
    LEFT JOIN refresh_token_families f ON f.id=s.refresh_family_id
    WHERE f.id IS NULL;
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % auth sessions reference a missing refresh family', broken; END IF;

    SELECT count(*) INTO broken
    FROM refresh_token_families f
    JOIN auth_sessions s ON s.id=f.session_id
    WHERE s.user_id<>f.user_id OR s.refresh_family_id<>f.id;
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % refresh families disagree with their session/user', broken; END IF;

    SELECT count(*) INTO broken
    FROM refresh_tokens t
    JOIN refresh_token_families f ON f.id=t.family_id
    WHERE t.session_id<>f.session_id;
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % refresh tokens disagree with their family session', broken; END IF;

    SELECT count(*) INTO broken FROM (
        SELECT family_id FROM refresh_tokens WHERE status='current' GROUP BY family_id HAVING count(*)>1
    ) q;
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % refresh families have more than one current token', broken; END IF;

    SELECT count(*) INTO broken
    FROM provider_credentials pc
    LEFT JOIN auth_identities ai ON ai.id=pc.identity_id
    WHERE ai.id IS NULL OR ai.user_id<>pc.user_id OR ai.provider<>pc.provider OR ai.subject<>pc.subject;
    IF broken <> 0 THEN RAISE EXCEPTION '0.11.10 migration refused: % provider credentials disagree with canonical identity', broken; END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_status_check') THEN
        ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_status_check CHECK (status IN ('active','revoked'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_token_families_status_check') THEN
        ALTER TABLE refresh_token_families ADD CONSTRAINT refresh_token_families_status_check CHECK (status IN ('active','revoked','compromised'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_tokens_status_check') THEN
        ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_status_check CHECK (status IN ('current','consumed','revoked'));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_one_current_per_family
    ON refresh_tokens(family_id) WHERE status='current';

-- Composite unique keys make cross-table ownership enforceable by foreign keys.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_token_families_id_session_user_key') THEN
        ALTER TABLE refresh_token_families
            ADD CONSTRAINT refresh_token_families_id_session_user_key UNIQUE(id,session_id,user_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_token_families_id_session_key') THEN
        ALTER TABLE refresh_token_families
            ADD CONSTRAINT refresh_token_families_id_session_key UNIQUE(id,session_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_identities_id_user_provider_subject_key') THEN
        ALTER TABLE auth_identities
            ADD CONSTRAINT auth_identities_id_user_provider_subject_key UNIQUE(id,user_id,provider,subject);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_refresh_family_consistency_fk') THEN
        ALTER TABLE auth_sessions
            ADD CONSTRAINT auth_sessions_refresh_family_consistency_fk
            FOREIGN KEY(refresh_family_id,id,user_id)
            REFERENCES refresh_token_families(id,session_id,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_tokens_family_session_consistency_fk') THEN
        ALTER TABLE refresh_tokens
            ADD CONSTRAINT refresh_tokens_family_session_consistency_fk
            FOREIGN KEY(family_id,session_id)
            REFERENCES refresh_token_families(id,session_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='provider_credentials_identity_consistency_fk') THEN
        ALTER TABLE provider_credentials
            ADD CONSTRAINT provider_credentials_identity_consistency_fk
            FOREIGN KEY(identity_id,user_id,provider,subject)
            REFERENCES auth_identities(id,user_id,provider,subject)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_auth_events_session_created
    ON auth_events(session_id,created_at DESC) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_events_type_created
    ON auth_events(event_type,created_at DESC);
