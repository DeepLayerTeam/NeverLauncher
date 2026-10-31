-- 0.26.8: a verified Minecraft UUID may belong to only one Never identity.
-- No OAuth, Xbox, XSTS or Minecraft bearer tokens are persisted here.
CREATE TABLE official_never_identity_links_0268 (
  minecraft_uuid CHAR(32) PRIMARY KEY CHECK (minecraft_uuid ~ '^[0-9a-f]{32}$'),
  never_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  minecraft_name VARCHAR(16) NOT NULL CHECK (minecraft_name ~ '^[A-Za-z0-9_]{3,16}$'),
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_official_never_identity_owner_0268 ON official_never_identity_links_0268(never_user_id);
