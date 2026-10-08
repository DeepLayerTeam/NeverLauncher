-- NeverLauncher 0.14.2 — Криптографический Узел Идентичности.
-- ServerBridge узлы аутентифицировать каждый привилегированный запрос с Ed25519
-- подпись. PostgreSQL хранит только публичный идентичность материал и использованный одноразовые значения;
-- устаревший 0.14.1 bearer хеширует являются выведенный из эксплуатации и никогда принят через 0.14.2 среда выполнения.

ALTER TABLE server_bridge_nodes_v2
    ADD COLUMN IF NOT EXISTS key_algorithm TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS public_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS key_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS identity_epoch BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS identity_rotated_at TIMESTAMPTZ;

ALTER TABLE server_bridge_nodes_v2
    DROP CONSTRAINT IF EXISTS server_bridge_nodes_v2_status_check;

-- Bearer учётные данные являются выведенный из эксплуатации глобально, включая отключённый узлы. Сохранять 
-- unusable устаревший учётные данные хеш будет добавлять секрет-производный материал с нет
-- эксплуатационный назначение после криптографический идентичность граница изменять.
UPDATE server_bridge_nodes_v2
SET token_hash='', token_prefix=''
WHERE token_hash<>'' OR token_prefix<>'';

UPDATE server_bridge_nodes_v2
SET status='identity-enrollment-required',
    token_hash='',
    token_prefix='',
    key_algorithm='',
    public_key='',
    key_fingerprint='',
    identity_epoch=0,
    identity_rotated_at=NULL,
    plugin_version='',
    plugin_sha256='',
    integrity_status='',
    integrity_verified_at=NULL,
    last_heartbeat_at=NULL
WHERE status IN ('active','credential-rotation-required');

ALTER TABLE server_bridge_nodes_v2
    ADD CONSTRAINT server_bridge_nodes_v2_status_check
        CHECK (status IN ('active','disabled','identity-enrollment-required')),
    ADD CONSTRAINT server_bridge_nodes_v2_identity_algorithm_check
        CHECK (key_algorithm IN ('','ed25519')),
    ADD CONSTRAINT server_bridge_nodes_v2_public_key_check
        CHECK (public_key = '' OR public_key ~ '^[A-Za-z0-9_-]{43}$'),
    ADD CONSTRAINT server_bridge_nodes_v2_key_fingerprint_check
        CHECK (key_fingerprint = '' OR key_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT server_bridge_nodes_v2_identity_epoch_check
        CHECK (identity_epoch >= 0),
    ADD CONSTRAINT server_bridge_nodes_v2_active_identity_check
        CHECK (
            status <> 'active' OR
            (
                key_algorithm='ed25519' AND
                public_key ~ '^[A-Za-z0-9_-]{43}$' AND
                key_fingerprint ~ '^[0-9a-f]{64}$' AND
                identity_epoch >= 1 AND
                token_hash='' AND token_prefix=''
            )
        );

CREATE UNIQUE INDEX IF NOT EXISTS uq_server_bridge_nodes_v2_key_fingerprint
    ON server_bridge_nodes_v2(key_fingerprint)
    WHERE key_fingerprint <> '';

CREATE TABLE IF NOT EXISTS server_bridge_node_nonces_v2 (
    node_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
    nonce_hash TEXT NOT NULL,
    identity_epoch BIGINT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(node_id, nonce_hash),
    CONSTRAINT server_bridge_node_nonces_v2_hash_check CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT server_bridge_node_nonces_v2_epoch_check CHECK (identity_epoch >= 1),
    CONSTRAINT server_bridge_node_nonces_v2_expiry_check CHECK (expires_at > consumed_at AND expires_at <= consumed_at + interval '5 minutes')
);
CREATE INDEX IF NOT EXISTS idx_server_bridge_node_nonces_v2_expiry
    ON server_bridge_node_nonces_v2(expires_at);

-- Активный подключается аутентифицировать под выведенный из эксплуатации bearer идентичность должен не переживать 
-- идентичность граница изменять. Актуальный подключается являются выданный только после узел регистрация.
UPDATE server_bridge_join_tickets_v2
SET status='invalidated', invalidated_at=now()
WHERE status='active';
