-- NeverLauncher 0.11.2 — Federation Core identity metadata.
-- auth_identities already exists since 0.11.1; this migration upgrades it from a
-- simple link table into the canonical provider identity record used by Federation Core.

ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS username TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS claims JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE auth_identities ADD COLUMN IF NOT EXISTS last_authenticated_at TIMESTAMPTZ;

UPDATE auth_identities ai
SET email = u.email,
    username = u.email,
    display_name = u.display_name,
    updated_at = now()
FROM users u
WHERE ai.user_id = u.id
  AND ai.provider = 'local'
  AND (ai.email = '' OR ai.username = '' OR ai.display_name = '');

CREATE INDEX IF NOT EXISTS idx_auth_identities_user_provider ON auth_identities(user_id, provider);
CREATE INDEX IF NOT EXISTS idx_auth_identities_provider_email ON auth_identities(provider, lower(email)) WHERE email <> '';
