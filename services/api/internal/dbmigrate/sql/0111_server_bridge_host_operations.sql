-- Durable boundary across Backend, RemoteControl and a real Host Supervisor.
-- One uncertain operation per host prevents different idempotency keys from
-- bypassing an indeterminate result. All new commands require PostgreSQL.
CREATE TABLE server_bridge_host_operations_0413 (
 id TEXT PRIMARY KEY,
 server_id TEXT NOT NULL REFERENCES server_bridge_nodes_v2(id) ON DELETE CASCADE,
 action TEXT NOT NULL CHECK(action IN ('start','stop','restart')),
 requested_by TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 request_digest CHAR(64) NOT NULL,
 remote_node_id TEXT NOT NULL,
 baseline_runtime_id TEXT NOT NULL DEFAULT '',
 baseline_runtime_epoch BIGINT NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'indeterminate' CHECK(status IN ('indeterminate','accepted','succeeded')),
 host_before JSONB NOT NULL DEFAULT '{}'::jsonb,
 host_after JSONB NOT NULL DEFAULT '{}'::jsonb,
 remote_receipt JSONB NOT NULL DEFAULT '{}'::jsonb,
 error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(server_id,idempotency_key)
);
CREATE UNIQUE INDEX server_bridge_host_unresolved_0413 ON server_bridge_host_operations_0413(server_id)
 WHERE status='indeterminate';
CREATE INDEX server_bridge_host_operations_recent_0413 ON server_bridge_host_operations_0413(server_id,created_at DESC);
CREATE OR REPLACE FUNCTION server_bridge_host_receipt_fence_0413() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='succeeded' THEN RAISE EXCEPTION 'verified host receipt is immutable' USING ERRCODE='23514'; END IF;
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.server_id IS DISTINCT FROM OLD.server_id OR NEW.action IS DISTINCT FROM OLD.action
 OR NEW.request_digest IS DISTINCT FROM OLD.request_digest OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
 OR NEW.remote_node_id IS DISTINCT FROM OLD.remote_node_id OR NEW.host_before IS DISTINCT FROM OLD.host_before
 OR NEW.baseline_runtime_id IS DISTINCT FROM OLD.baseline_runtime_id OR NEW.baseline_runtime_epoch IS DISTINCT FROM OLD.baseline_runtime_epoch THEN
 RAISE EXCEPTION 'host command identity is immutable' USING ERRCODE='23514'; END IF;
 IF OLD.status='accepted' AND NEW.status='indeterminate' THEN RAISE EXCEPTION 'host operation cannot regress' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER server_bridge_host_receipt_fence_0413 BEFORE UPDATE ON server_bridge_host_operations_0413
 FOR EACH ROW EXECUTE FUNCTION server_bridge_host_receipt_fence_0413();
