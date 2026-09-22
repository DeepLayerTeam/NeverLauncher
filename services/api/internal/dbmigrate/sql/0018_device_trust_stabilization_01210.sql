-- NeverLauncher 0.12.10 — Device Trust migration + stabilization.
--
-- This migration closes the relational gaps left intentionally open while the
-- Device Trust lifecycle was being built across 0.12.1–0.12.9. It is fail-closed
-- for ownership/corruption problems, but safely normalizes states that older
-- releases could legitimately leave behind (revoked-device attestation state,
-- empty-string optional references and expired one-shot challenges).

-- 0.12.8 introduced key-rotate/key-recover challenges, but the 0.12.4 purpose
-- constraint still allowed only register/session-bind/attest. Drop it before the
-- validation block so production PostgreSQL can actually persist replacement
-- challenges after this migration.
ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_purpose_check;

-- Empty-string replacement links were a storage sentinel in 0.12.8. Convert the
-- optional relation to SQL NULL so it can be protected by a real foreign key.
ALTER TABLE trusted_devices ALTER COLUMN replaced_by_device_id DROP NOT NULL;
ALTER TABLE trusted_devices ALTER COLUMN replaced_by_device_id DROP DEFAULT;
UPDATE trusted_devices SET replaced_by_device_id=NULL WHERE btrim(COALESCE(replaced_by_device_id,''))='';

-- Revoked rows created before challenge-response attestation existed can carry
-- attestation_state='unattested'. Revocation is stronger than attestation state,
-- so normalize them without granting any trust.
UPDATE trusted_devices
SET trust_state='revoked',
    assurance='proof-of-possession',
    attestation_state='revoked',
    attestation_method='',
    attested_at=NULL,
    attestation_expires_at=NULL,
    revoked_at=COALESCE(revoked_at,updated_at,now()),
    revoked_reason=CASE WHEN btrim(revoked_reason)='' THEN 'legacy-device-revoked' ELSE revoked_reason END
WHERE status='revoked';

-- Expired one-shot challenges no longer need to remain pending. Marking them
-- consumed is security-preserving and keeps the partial expiry index bounded.
UPDATE device_challenges
SET consumed_at=expires_at
WHERE consumed_at IS NULL AND expires_at<=now();

-- Optional Minecraft trust snapshots used '' before 0.12.10. NULL preserves the
-- legacy-Yggdrasil compatibility path while allowing ownership FKs below.
ALTER TABLE minecraft_sessions ALTER COLUMN trusted_device_id DROP NOT NULL;
ALTER TABLE minecraft_sessions ALTER COLUMN trusted_device_id DROP DEFAULT;
UPDATE minecraft_sessions SET trusted_device_id=NULL WHERE btrim(COALESCE(trusted_device_id,''))='';

DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken
    FROM trusted_devices
    WHERE status='active'
      AND (trust_state<>'verified' OR attestation_state='revoked' OR revoked_at IS NOT NULL OR btrim(revoked_reason)<>'');
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % active trusted device row(s) have revoked/inconsistent lifecycle state', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM trusted_devices d
    LEFT JOIN trusted_devices n ON n.id=d.replaced_by_device_id
    WHERE d.replaced_by_device_id IS NOT NULL
      AND (
        d.replaced_by_device_id=d.id OR
        d.replaced_at IS NULL OR
        d.replacement_reason NOT IN ('rotate','recover') OR
        d.status<>'revoked' OR d.trust_state<>'revoked' OR d.attestation_state<>'revoked' OR
        n.id IS NULL OR n.user_id<>d.user_id
      );
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % trusted device replacement link(s) are invalid or cross-user', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM trusted_devices
    WHERE replaced_by_device_id IS NULL
      AND (replaced_at IS NOT NULL OR btrim(replacement_reason)<>'');
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % trusted device row(s) contain partial replacement metadata', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM auth_sessions s
    JOIN trusted_devices d ON d.id=s.trusted_device_id
    WHERE s.trusted_device_id IS NOT NULL AND d.user_id<>s.user_id;
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % auth session(s) reference a trusted device owned by another user', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM auth_sessions
    WHERE (trusted_device_id IS NULL AND device_trust_state<>'unverified')
       OR (trusted_device_id IS NOT NULL AND device_trust_state='unverified')
       OR (status='active' AND device_trust_state='revoked');
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % auth session(s) have an impossible trusted-device binding shape', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM minecraft_sessions m
    JOIN auth_sessions s ON s.id=m.never_session_id
    WHERE s.user_id<>m.user_id;
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % Minecraft session(s) disagree with parent Never session ownership', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM minecraft_sessions m
    JOIN minecraft_profiles p ON p.uuid=m.profile_uuid
    WHERE p.user_id<>m.user_id;
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % Minecraft session(s) disagree with profile ownership', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM minecraft_sessions m
    JOIN trusted_devices d ON d.id=m.trusted_device_id
    WHERE m.trusted_device_id IS NOT NULL AND d.user_id<>m.user_id;
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.10 migration refused: % Minecraft session(s) reference a trusted device owned by another user', broken;
    END IF;
END $$;

-- Canonical device challenge purposes now cover the complete shipping lifecycle.
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_purpose_check
    CHECK (purpose IN ('register','session-bind','attest','key-rotate','key-recover'));
ALTER TABLE device_challenges DROP CONSTRAINT IF EXISTS device_challenges_metadata_object_check;
ALTER TABLE device_challenges ADD CONSTRAINT device_challenges_metadata_object_check
    CHECK (jsonb_typeof(metadata)='object');

-- Internal lifecycle shape: revocation cannot be represented as an active trusted
-- device, and replacement metadata must be complete or absent.
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_lifecycle_check;
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_lifecycle_check CHECK (
    (status='active' AND trust_state='verified' AND attestation_state IN ('unattested','verified') AND revoked_at IS NULL AND btrim(revoked_reason)='') OR
    (status='revoked' AND trust_state='revoked' AND assurance='proof-of-possession' AND attestation_state='revoked' AND revoked_at IS NOT NULL AND btrim(revoked_reason)<>'')
);
ALTER TABLE trusted_devices DROP CONSTRAINT IF EXISTS trusted_devices_replacement_shape_check;
ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_replacement_shape_check CHECK (
    (replaced_by_device_id IS NULL AND replaced_at IS NULL AND btrim(replacement_reason)='') OR
    (replaced_by_device_id IS NOT NULL AND replaced_by_device_id<>id AND replaced_at IS NOT NULL
        AND replacement_reason IN ('rotate','recover') AND status='revoked' AND trust_state='revoked' AND attestation_state='revoked')
);

ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_device_binding_shape_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_device_binding_shape_check CHECK (
    ((trusted_device_id IS NULL AND device_trust_state='unverified') OR
     (trusted_device_id IS NOT NULL AND device_trust_state IN ('verified','revoked')))
    AND NOT (status='active' AND device_trust_state='revoked')
);

-- Composite ownership keys allow the database to reject cross-user references,
-- not merely rely on HTTP/repository checks.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='trusted_devices_id_user_key' AND conrelid='trusted_devices'::regclass) THEN
        ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_id_user_key UNIQUE(id,user_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_id_user_key' AND conrelid='auth_sessions'::regclass) THEN
        ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_id_user_key UNIQUE(id,user_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='minecraft_profiles_uuid_user_key' AND conrelid='minecraft_profiles'::regclass) THEN
        ALTER TABLE minecraft_profiles ADD CONSTRAINT minecraft_profiles_uuid_user_key UNIQUE(uuid,user_id);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_sessions_trusted_device_owner_fk' AND conrelid='auth_sessions'::regclass) THEN
        ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_trusted_device_owner_fk
            FOREIGN KEY(trusted_device_id,user_id) REFERENCES trusted_devices(id,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='trusted_devices_replacement_owner_fk' AND conrelid='trusted_devices'::regclass) THEN
        ALTER TABLE trusted_devices ADD CONSTRAINT trusted_devices_replacement_owner_fk
            FOREIGN KEY(replaced_by_device_id,user_id) REFERENCES trusted_devices(id,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='minecraft_sessions_never_session_owner_fk' AND conrelid='minecraft_sessions'::regclass) THEN
        ALTER TABLE minecraft_sessions ADD CONSTRAINT minecraft_sessions_never_session_owner_fk
            FOREIGN KEY(never_session_id,user_id) REFERENCES auth_sessions(id,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='minecraft_sessions_device_owner_fk' AND conrelid='minecraft_sessions'::regclass) THEN
        ALTER TABLE minecraft_sessions ADD CONSTRAINT minecraft_sessions_device_owner_fk
            FOREIGN KEY(trusted_device_id,user_id) REFERENCES trusted_devices(id,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='minecraft_sessions_profile_owner_fk' AND conrelid='minecraft_sessions'::regclass) THEN
        ALTER TABLE minecraft_sessions ADD CONSTRAINT minecraft_sessions_profile_owner_fk
            FOREIGN KEY(profile_uuid,user_id) REFERENCES minecraft_profiles(uuid,user_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_device_challenges_pending_user_purpose
    ON device_challenges(user_id,purpose,expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_trusted_devices_replacement_chain
    ON trusted_devices(user_id,replaced_at DESC)
    WHERE replaced_by_device_id IS NOT NULL;
