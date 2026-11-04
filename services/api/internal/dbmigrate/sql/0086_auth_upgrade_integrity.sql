-- 0.29.11: enforce canonical owner immutability at the database boundary.
-- Legitimate account linking INSERTs a new verified identity; authentication
-- updates claims / last_authenticated_at, never rewrites its canonical key.
DO $nl$
BEGIN
 IF EXISTS (SELECT 1 FROM auth_identities WHERE id IS NULL OR user_id IS NULL OR provider IS NULL OR issuer IS NULL OR subject IS NULL) THEN
  RAISE EXCEPTION '0.29.11 refused: incomplete auth identity';
 END IF;
 IF EXISTS (SELECT 1 FROM auth_identities WHERE issuer='' OR issuer<>btrim(issuer) OR subject='') THEN
  RAISE EXCEPTION '0.29.11 refused: malformed issuer or subject';
 END IF;
 IF EXISTS (SELECT 1 FROM auth_identities i LEFT JOIN users u ON u.id=i.user_id WHERE u.id IS NULL) THEN
  RAISE EXCEPTION '0.29.11 refused: auth identities without Never account';
 END IF;
 IF EXISTS (SELECT 1 FROM minecraft_profiles m LEFT JOIN users u ON u.id=m.user_id WHERE u.id IS NULL) THEN
  RAISE EXCEPTION '0.29.11 refused: Minecraft profiles without Never account';
 END IF;
END
$nl$;

CREATE OR REPLACE FUNCTION nl_preserve_auth_owner_02911() RETURNS trigger AS $nl$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id
 OR NEW.user_id IS DISTINCT FROM OLD.user_id
 OR NEW.provider IS DISTINCT FROM OLD.provider
 OR NEW.issuer IS DISTINCT FROM OLD.issuer
 OR NEW.subject IS DISTINCT FROM OLD.subject THEN
  RAISE EXCEPTION '0.29.11: identity ownership and verified issuer/subject are immutable; create a separately proven link';
 END IF;
 RETURN NEW;
END
$nl$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_preserve_auth_owner_02911 ON auth_identities;
CREATE TRIGGER trg_preserve_auth_owner_02911 BEFORE UPDATE ON auth_identities
FOR EACH ROW EXECUTE FUNCTION nl_preserve_auth_owner_02911();
