-- NeverLauncher 0.12.7 — Minecraft / ServerBridge доверие принудительное применение.
-- Закреплять каждый сохранённый Minecraft учётные данные к родительский Никогда сессия устройство
-- привязка эпоха. Существующий активный учётные данные являются backfilled из текущий
-- родительский сессия так в-place обновление делает не fabricate другой доверие
-- снимок; любой позже re-привязывать немедленно инвалидирует старый учётные данные.

ALTER TABLE minecraft_sessions
    ADD COLUMN IF NOT EXISTS trusted_device_id TEXT NOT NULL DEFAULT '';
ALTER TABLE minecraft_sessions
    ADD COLUMN IF NOT EXISTS binding_epoch BIGINT NOT NULL DEFAULT 1;

UPDATE minecraft_sessions m
SET trusted_device_id = COALESCE(a.trusted_device_id, ''),
    binding_epoch = GREATEST(COALESCE(a.binding_epoch, 1), 1)
FROM auth_sessions a
WHERE a.id = m.never_session_id
  AND (m.trusted_device_id = '' OR m.binding_epoch = 1);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'minecraft_sessions_binding_epoch_check'
          AND conrelid = 'minecraft_sessions'::regclass
    ) THEN
        ALTER TABLE minecraft_sessions
            ADD CONSTRAINT minecraft_sessions_binding_epoch_check
            CHECK (binding_epoch >= 1);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_minecraft_sessions_trust_binding
    ON minecraft_sessions(never_session_id, trusted_device_id, binding_epoch, status);
