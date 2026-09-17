-- NeverLauncher 0.12.6 — authoritative Session <-> Device binding + risk integration.
-- binding_epoch invalidates access tokens minted before a device bind/re-bind.
-- risk_score/risk_action make device/network risk an enforced session decision rather
-- than an informational label.

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS binding_epoch BIGINT NOT NULL DEFAULT 1;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_score SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_action TEXT NOT NULL DEFAULT 'allow';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS risk_evaluated_at TIMESTAMPTZ;

UPDATE auth_sessions
SET binding_epoch = GREATEST(binding_epoch, 1),
    risk_score = CASE
        WHEN risk_state='compromised' THEN 100
        WHEN risk_state='elevated' THEN GREATEST(risk_score, 25)
        ELSE GREATEST(risk_score, 0)
    END,
    risk_action = CASE
        WHEN risk_state='compromised' THEN 'revoke'
        WHEN risk_state='elevated' THEN 'step-up'
        ELSE 'allow'
    END
WHERE binding_epoch < 1
   OR risk_score < 0
   OR risk_action NOT IN ('allow','step-up','reattest','revoke')
   OR (risk_state='compromised' AND risk_action<>'revoke')
   OR (risk_state='elevated' AND risk_action='allow');

ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_binding_epoch_check;
ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_risk_score_check;
ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS auth_sessions_risk_action_check;

ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_binding_epoch_check
    CHECK (binding_epoch >= 1);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_risk_score_check
    CHECK (risk_score BETWEEN 0 AND 100);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_risk_action_check
    CHECK (risk_action IN ('allow','step-up','reattest','revoke'));

CREATE INDEX IF NOT EXISTS idx_auth_sessions_binding_epoch
    ON auth_sessions(id,binding_epoch)
    WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_auth_sessions_risk_action_active
    ON auth_sessions(risk_action,risk_score DESC,last_seen_at DESC)
    WHERE status='active';
