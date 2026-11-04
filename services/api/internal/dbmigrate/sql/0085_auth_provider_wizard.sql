-- Managed, non-secret provider settings. Never persist DSNs, client secrets,
-- passwords or refresh/access tokens; config is validated before insertion.
CREATE TABLE auth_provider_heads_02910 (
 provider_id text PRIMARY KEY CHECK(length(provider_id) BETWEEN 2 AND 64),
 active_revision bigint NOT NULL DEFAULT 0 CHECK(active_revision>=0)
);
CREATE TABLE auth_provider_revisions_02910 (
 provider_id text NOT NULL REFERENCES auth_provider_heads_02910(provider_id),
 revision bigint NOT NULL CHECK(revision>0),
 kind text NOT NULL CHECK(kind IN ('sql','http','oidc','microsoft')),
 config jsonb NOT NULL,
 actor text NOT NULL,
 reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(provider_id,revision)
);
CREATE TABLE auth_provider_activation_audit_02910 (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 provider_id text NOT NULL REFERENCES auth_provider_heads_02910(provider_id),
 from_revision bigint NOT NULL,
 to_revision bigint NOT NULL,
 actor text NOT NULL,
 reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
