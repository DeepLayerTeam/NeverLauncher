-- Version 0.26.11: public app policy, CAS revisions, durable audit history.
-- No OAuth client secret, access token or refresh token is ever stored here.
CREATE TABLE official_provider_config_02611 (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
 revision BIGINT NOT NULL CHECK (revision > 0),
 client_id VARCHAR(36) NOT NULL,
 enabled BOOLEAN NOT NULL,
 browser_enabled BOOLEAN NOT NULL,
 device_enabled BOOLEAN NOT NULL,
 issuer TEXT NOT NULL CHECK (issuer = 'consumers'),
 actor TEXT NOT NULL,
 reason VARCHAR(500) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE official_provider_history_02611 (
 revision BIGINT PRIMARY KEY CHECK (revision > 0),
 client_id VARCHAR(36) NOT NULL,
 enabled BOOLEAN NOT NULL,
 browser_enabled BOOLEAN NOT NULL,
 device_enabled BOOLEAN NOT NULL,
 issuer TEXT NOT NULL CHECK (issuer = 'consumers'),
 actor TEXT NOT NULL,
 reason VARCHAR(500) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL
);
