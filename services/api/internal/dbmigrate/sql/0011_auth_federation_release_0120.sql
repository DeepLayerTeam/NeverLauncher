-- NeverLauncher 0.12.0 — Auth Federation Release invariants.
-- Local password authentication is a first-class provider and must obey the same
-- canonical identity boundary as SQL/HTTP/OIDC/Microsoft providers.

-- Backfill canonical local identities for every password-capable Never user.
INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at)
SELECT 'identity-local-' || u.id, u.id, 'local', u.id, u.email, u.email, u.display_name, '{}'::jsonb, now(), now()
FROM users u
LEFT JOIN auth_identities ai ON ai.user_id=u.id AND ai.provider='local'
WHERE btrim(coalesce(u.password_hash,''))<>'' AND ai.id IS NULL
ON CONFLICT DO NOTHING;

-- Normalize stale local identity metadata without altering external identities.
UPDATE auth_identities ai
SET subject=u.id,
    email=u.email,
    username=u.email,
    display_name=u.display_name,
    updated_at=now()
FROM users u
WHERE ai.user_id=u.id AND ai.provider='local'
  AND (ai.subject<>u.id OR ai.email<>u.email OR ai.username<>u.email OR ai.display_name<>u.display_name);

DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken
    FROM users u
    LEFT JOIN auth_identities ai ON ai.user_id=u.id AND ai.provider='local'
    WHERE btrim(coalesce(u.password_hash,''))<>''
      AND (ai.id IS NULL OR ai.subject<>u.id);
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.0 migration refused: % password-capable users lack a canonical local identity', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM auth_identities
    WHERE provider<>lower(btrim(provider)) OR provider='' OR subject<>btrim(subject) OR subject='';
    IF broken<>0 THEN
        RAISE EXCEPTION '0.12.0 migration refused: % auth identities contain non-canonical provider/subject values', broken;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_identities_provider_canonical_check') THEN
        ALTER TABLE auth_identities ADD CONSTRAINT auth_identities_provider_canonical_check
            CHECK (provider<>'' AND provider=lower(btrim(provider)));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='auth_identities_subject_canonical_check') THEN
        ALTER TABLE auth_identities ADD CONSTRAINT auth_identities_subject_canonical_check
            CHECK (subject<>'' AND subject=btrim(subject));
    END IF;
END $$;

-- Deferred constraint triggers keep password-capable users and local identities
-- consistent even when a user/password and its identity are changed in one transaction.
CREATE OR REPLACE FUNCTION neverlauncher_check_local_identity_for_user() RETURNS trigger AS $$
DECLARE local_subject TEXT;
BEGIN
    IF btrim(coalesce(NEW.password_hash,''))='' THEN
        RETURN NEW;
    END IF;
    SELECT subject INTO local_subject FROM auth_identities WHERE user_id=NEW.id AND provider='local';
    IF local_subject IS NULL OR local_subject<>NEW.id THEN
        RAISE EXCEPTION 'password-capable user % must have local identity subject equal to user id', NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_require_local_identity ON users;
CREATE CONSTRAINT TRIGGER trg_users_require_local_identity
AFTER INSERT OR UPDATE OF password_hash ON users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION neverlauncher_check_local_identity_for_user();

CREATE OR REPLACE FUNCTION neverlauncher_check_local_identity_change() RETURNS trigger AS $$
DECLARE uid TEXT;
DECLARE pwd TEXT;
DECLARE local_subject TEXT;
BEGIN
    uid := CASE WHEN TG_OP='DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF (TG_OP='INSERT' AND NEW.provider<>'local') OR (TG_OP='UPDATE' AND OLD.provider<>'local' AND NEW.provider<>'local') OR (TG_OP='DELETE' AND OLD.provider<>'local') THEN
        IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    SELECT password_hash INTO pwd FROM users WHERE id=uid;
    IF btrim(coalesce(pwd,''))='' THEN
        IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    SELECT subject INTO local_subject FROM auth_identities WHERE user_id=uid AND provider='local';
    IF local_subject IS NULL OR local_subject<>uid THEN
        RAISE EXCEPTION 'cannot remove or corrupt local identity for password-capable user %', uid;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auth_identities_preserve_local ON auth_identities;
CREATE CONSTRAINT TRIGGER trg_auth_identities_preserve_local
AFTER INSERT OR UPDATE OR DELETE ON auth_identities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION neverlauncher_check_local_identity_change();

CREATE INDEX IF NOT EXISTS idx_auth_identities_provider_subject_user
    ON auth_identities(provider,subject,user_id);
