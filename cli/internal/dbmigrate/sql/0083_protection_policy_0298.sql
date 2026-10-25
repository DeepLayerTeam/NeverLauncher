-- Protection bans are authoritative, auditable and independent of user.status.
CREATE TABLE protection_bans (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 3 AND 512),
  actor TEXT NOT NULL CHECK (length(trim(actor)) > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT
);
CREATE INDEX idx_protection_bans_active ON protection_bans (expires_at) WHERE revoked_at IS NULL;
-- A ban blocks all already-issued auth, Minecraft and ServerBridge credentials,
-- including on other API replicas, by using the 0.29.7 cascade.
CREATE OR REPLACE FUNCTION nl_protection_ban_sessions_0298()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked_at IS NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > now()) THEN
        UPDATE auth_sessions SET status='revoked', revoked_at=now(), revoked_reason='protection-ban'
        WHERE user_id=NEW.user_id AND status='active';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER nl_protection_ban_sessions_0298 AFTER INSERT OR UPDATE OF revoked_at,expires_at,reason ON protection_bans
FOR EACH ROW EXECUTE FUNCTION nl_protection_ban_sessions_0298();
-- Race fence: new auth sessions cannot be inserted after an active ban committed.
CREATE OR REPLACE FUNCTION nl_protection_check_session_0298()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE locked_user TEXT;
BEGIN
    -- Row lock pairs with SetProtectionBan to serialize concurrent login/ban.
    SELECT id INTO locked_user FROM users WHERE id=NEW.user_id FOR UPDATE;
    IF EXISTS(SELECT 1 FROM protection_bans WHERE user_id=NEW.user_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())) THEN
      RAISE EXCEPTION 'protection policy denied authentication' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER nl_protection_check_session_0298 BEFORE INSERT ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION nl_protection_check_session_0298();
