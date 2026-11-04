-- Durable, once-per-idempotency-key restart scheduling. The operator must target an
-- observed runtime identity, and an already accepted action is never replayed.
CREATE TABLE IF NOT EXISTS backend_restart_requests_0289 (
 id text PRIMARY KEY CHECK (length(id) = 64),
 actor text NOT NULL CHECK (length(actor) > 0),
 instance_id text NOT NULL CHECK (length(instance_id) > 0),
 state text NOT NULL DEFAULT 'accepted' CHECK (state IN ('accepted')),
 accepted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS backend_restart_requests_0289_created ON backend_restart_requests_0289(accepted_at DESC);

-- Durable user-targeted Backend notices. The receiving client must authenticate
-- as the recipient and explicitly acknowledge receipt (not just a successful poll).
CREATE TABLE IF NOT EXISTS backend_notices_0289 (
 id text PRIMARY KEY CHECK (length(id) = 64),
 actor text NOT NULL,
 recipient_user_id text NOT NULL,
 body text NOT NULL CHECK (length(body) BETWEEN 1 AND 512),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours'),
 acknowledged_at timestamptz
);
CREATE INDEX IF NOT EXISTS backend_notices_0289_inbox
 ON backend_notices_0289(recipient_user_id,created_at DESC)
 WHERE acknowledged_at IS NULL;
-- Prevent a different idempotency key from scheduling a second restart on an
-- instance whose first request has already been accepted.
CREATE UNIQUE INDEX IF NOT EXISTS backend_restart_requests_0289_once_per_instance
 ON backend_restart_requests_0289(instance_id);
