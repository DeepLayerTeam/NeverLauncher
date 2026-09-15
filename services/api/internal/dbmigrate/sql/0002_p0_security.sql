-- NeverLauncher 0.10.0-P0 installation/bootstrap security state.
CREATE TABLE IF NOT EXISTS neverlauncher_installation_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 bootstrap_token_hash TEXT NOT NULL DEFAULT '',
 bootstrap_token_used_at TIMESTAMPTZ,
 installation_completed BOOLEAN NOT NULL DEFAULT FALSE,
 completed_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO neverlauncher_installation_state(singleton) VALUES(TRUE) ON CONFLICT(singleton) DO NOTHING;
UPDATE neverlauncher_installation_state
SET installation_completed = TRUE,
    completed_at = COALESCE(completed_at, now()),
    updated_at = now()
WHERE singleton = TRUE
  AND installation_completed = FALSE
  AND EXISTS (SELECT 1 FROM users LIMIT 1)
  AND EXISTS (SELECT 1 FROM projects LIMIT 1);
