CREATE TABLE IF NOT EXISTS ai_budget_months (month TEXT PRIMARY KEY, serial BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ai_requests (id TEXT PRIMARY KEY, month TEXT NOT NULL, user_id TEXT NOT NULL, model TEXT NOT NULL, started_at BIGINT NOT NULL, reserved_micro BIGINT NOT NULL CHECK(reserved_micro > 0), charged_micro BIGINT NOT NULL CHECK(charged_micro >= 0), input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, state TEXT NOT NULL CHECK(state IN ('reserved','completed','incomplete','uncertain')), FOREIGN KEY(month) REFERENCES ai_budget_months(month));
CREATE INDEX IF NOT EXISTS ai_requests_month_user ON ai_requests(month,user_id,started_at);
CREATE INDEX IF NOT EXISTS ai_requests_user_started ON ai_requests(user_id,started_at);
