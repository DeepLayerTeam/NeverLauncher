-- Launcher 0.14.3: одноразовые разрешения на вход.
--
-- Разрешения ServerBridge теперь привязаны к точной эпохе криптографической идентичности
-- узла на момент выдачи. При погашении хранится ранее аутентифицированное Ed25519-доказательство
-- nonce; успешное погашение выполняется единственным условным UPDATE. Стандартные
-- разрешения Yggdrasil /join -> /hasJoined также становятся одноразовыми.

-- Разрешения 0.14.2 не сохраняли привязку идентичности на момент выдачи. Они
-- краткосрочны, поэтому при обновлении отклоняйте их, не угадывая старую привязку.
UPDATE server_bridge_join_tickets_v2
SET status='invalidated', invalidated_at=now()
WHERE status='active';

ALTER TABLE server_bridge_join_tickets_v2
    ADD COLUMN IF NOT EXISTS ticket_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS issued_identity_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS issued_key_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS redeemed_identity_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS redeemed_key_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS redeemed_nonce_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS redeemed_by_ip TEXT NOT NULL DEFAULT '';

ALTER TABLE server_bridge_join_tickets_v2
    ALTER COLUMN ticket_version SET DEFAULT 2;

ALTER TABLE server_bridge_join_tickets_v2
    DROP CONSTRAINT IF EXISTS server_bridge_join_v2_ticket_version_check,
    DROP CONSTRAINT IF EXISTS server_bridge_join_v2_issued_identity_check,
    DROP CONSTRAINT IF EXISTS server_bridge_join_v2_redemption_proof_check;

ALTER TABLE server_bridge_join_tickets_v2
    ADD CONSTRAINT server_bridge_join_v2_ticket_version_check
        CHECK (ticket_version IN (1,2)),
    ADD CONSTRAINT server_bridge_join_v2_issued_identity_check
        CHECK (
            ticket_version = 1 OR
            (issued_identity_epoch >= 1 AND issued_key_fingerprint ~ '^[0-9a-f]{64}$')
        ),
    ADD CONSTRAINT server_bridge_join_v2_redemption_proof_check
        CHECK (
            ticket_version = 1 OR
            (
                (status = 'consumed'
                    AND redeemed_identity_epoch = issued_identity_epoch
                    AND redeemed_key_fingerprint = issued_key_fingerprint
                    AND redeemed_nonce_hash ~ '^[0-9a-f]{64}$')
                OR
                (status <> 'consumed'
                    AND redeemed_identity_epoch = 0
                    AND redeemed_key_fingerprint = ''
                    AND redeemed_nonce_hash = '')
            )
        );

CREATE INDEX IF NOT EXISTS idx_server_bridge_join_v2_latest_state_0143
    ON server_bridge_join_tickets_v2(server_id,username_normalized,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_join_v2_redemption_nonce_0143
    ON server_bridge_join_tickets_v2(server_id,redeemed_nonce_hash)
    WHERE ticket_version=2 AND status='consumed';

-- minecraft_joins — временная таблица совместимых разрешений на 120 секунд.
-- Старые строки нельзя считать одноразовыми, поскольку прежний /hasJoined лишь
-- читал их; на этой границе безопасности отбросьте их и начните заново.
DELETE FROM minecraft_joins;

ALTER TABLE minecraft_joins
    ADD COLUMN IF NOT EXISTS ticket_version INTEGER NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

ALTER TABLE minecraft_joins
    DROP CONSTRAINT IF EXISTS minecraft_joins_0143_ticket_version_check,
    DROP CONSTRAINT IF EXISTS minecraft_joins_0143_status_check,
    DROP CONSTRAINT IF EXISTS minecraft_joins_0143_terminal_check,
    DROP CONSTRAINT IF EXISTS minecraft_joins_0143_expiry_check;

ALTER TABLE minecraft_joins
    ADD CONSTRAINT minecraft_joins_0143_ticket_version_check CHECK (ticket_version = 2),
    ADD CONSTRAINT minecraft_joins_0143_status_check CHECK (status IN ('active','consumed')),
    ADD CONSTRAINT minecraft_joins_0143_terminal_check CHECK (
        (status='active' AND consumed_at IS NULL) OR
        (status='consumed' AND consumed_at IS NOT NULL)
    ),
    ADD CONSTRAINT minecraft_joins_0143_expiry_check CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '2 minutes 5 seconds'
    );

CREATE INDEX IF NOT EXISTS idx_minecraft_joins_active_expires_0143
    ON minecraft_joins(expires_at) WHERE status='active';
