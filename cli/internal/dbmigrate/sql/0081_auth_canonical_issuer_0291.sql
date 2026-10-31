-- 0.29.1 Canonical Identity & Issuer: preserve every legacy identity and Minecraft UUID.
-- Existing external identities are bound to their stable provider namespace until
-- the account owner explicitly links a verified, protocol-level issuer. Never
-- infer the issuer from an unverified email or the current provider configuration.
ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS issuer TEXT;
UPDATE auth_identities
SET issuer = CASE WHEN provider='local' THEN 'launcher' ELSE 'provider:' || provider END
WHERE issuer IS NULL;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM auth_identities WHERE issuer IS NULL OR issuer='' OR issuer<>btrim(issuer) OR char_length(issuer)>2048) THEN
        RAISE EXCEPTION '0.29.1 refused: malformed auth issuer';
    END IF;
    IF EXISTS (SELECT 1 FROM auth_identities WHERE provider='local' AND issuer<>'launcher') THEN
        RAISE EXCEPTION '0.29.1 refused: local issuer mismatch';
    END IF;
    IF EXISTS (SELECT 1 FROM auth_identities GROUP BY provider,issuer,subject HAVING count(*)>1) THEN
        RAISE EXCEPTION '0.29.1 refused: duplicate issuer-scoped external subjects';
    END IF;
    IF EXISTS (SELECT 1 FROM auth_identities GROUP BY user_id,provider,issuer HAVING count(*)>1) THEN
        RAISE EXCEPTION '0.29.1 refused: multiple subjects of one issuer for one Never user';
    END IF;
END $$;

ALTER TABLE auth_identities ALTER COLUMN issuer SET NOT NULL;
ALTER TABLE auth_identities ADD CONSTRAINT auth_identities_issuer_canonical_0291
    CHECK (issuer<>'' AND issuer=btrim(issuer) AND char_length(issuer)<=2048
      AND issuer !~ '[[:space:][:cntrl:]]' AND (provider<>'local' OR issuer='launcher'));
ALTER TABLE auth_identities DROP CONSTRAINT IF EXISTS auth_identities_provider_subject_key;
ALTER TABLE auth_identities DROP CONSTRAINT IF EXISTS auth_identities_user_id_provider_key;
ALTER TABLE auth_identities ADD CONSTRAINT auth_identities_provider_issuer_subject_key UNIQUE(provider,issuer,subject);
ALTER TABLE auth_identities ADD CONSTRAINT auth_identities_user_provider_issuer_key UNIQUE(user_id,provider,issuer);
CREATE INDEX IF NOT EXISTS idx_auth_identities_issuer_user_0291 ON auth_identities(issuer,user_id);

-- The profile UUID is an independent, persistent game identity. A mistaken
-- migration, ORM UPDATE or administrative SQL statement cannot silently rewrite
-- it. Any future verified reassignment needs an explicit audited migration.
CREATE OR REPLACE FUNCTION nl_preserve_minecraft_uuid_0291() RETURNS trigger AS $$
BEGIN
    IF NEW.uuid IS DISTINCT FROM OLD.uuid OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.issuer IS DISTINCT FROM OLD.issuer OR NEW.realm IS DISTINCT FROM OLD.realm
        OR NEW.subject IS DISTINCT FROM OLD.subject THEN
        RAISE EXCEPTION '0.29.1: Minecraft UUID and canonical owner are immutable';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_preserve_minecraft_uuid_0291 ON minecraft_profiles;
CREATE TRIGGER trg_preserve_minecraft_uuid_0291 BEFORE UPDATE ON minecraft_profiles
FOR EACH ROW EXECUTE FUNCTION nl_preserve_minecraft_uuid_0291();

-- Refresh credentials are attached to verified identity IDs, not to a provider
-- slug (the same provider can represent distinct issuers).
ALTER TABLE provider_credentials DROP CONSTRAINT IF EXISTS provider_credentials_user_id_provider_key;
ALTER TABLE provider_credentials DROP CONSTRAINT IF EXISTS provider_credentials_provider_subject_key;
ALTER TABLE provider_credentials ADD CONSTRAINT provider_credentials_identity_id_key UNIQUE(identity_id);
