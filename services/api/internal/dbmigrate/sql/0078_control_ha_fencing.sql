-- 0.28.5: Never redeliver an external command whose previous lease lost its
-- ACK. The row is the durable evidence; Redis is an additional transient gate.
-- Existing unfinished deliveries cannot be proven unapplied during upgrade.
UPDATE server_bridge_control_commands_v3 SET
 status='indeterminate', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='migration: delivery was in progress; external effect unverified'
WHERE status='leased' AND (lease_until IS NULL OR lease_until<=now() OR expires_at<=now()
 OR NOT EXISTS (SELECT 1 FROM server_bridge_nodes_v2 n
  WHERE n.id=server_id AND n.status='active'
    AND n.runtime_epoch=server_bridge_control_commands_v3.runtime_epoch
    AND n.runtime_id=server_bridge_control_commands_v3.runtime_id));

UPDATE server_bridge_control_commands_v3 SET
 status='expired', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='expired before delivery'
WHERE status='pending' AND expires_at<=now();

-- Prevent old Backend replicas from silently re-leasing already delivered
-- commands during rolling deployments. Frozen token and owner are a fence.
CREATE OR REPLACE FUNCTION server_bridge_control_fence_0285() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('succeeded','failed','unsupported','indeterminate','expired') THEN
  RAISE EXCEPTION 'control command is terminal and immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.status='leased' THEN
  IF NEW.status='leased' THEN
   IF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
      OR NEW.lease_token IS DISTINCT FROM OLD.lease_token
      OR NEW.delivery_sequence IS DISTINCT FROM OLD.delivery_sequence
      OR NEW.runtime_epoch IS DISTINCT FROM OLD.runtime_epoch
      OR NEW.runtime_id IS DISTINCT FROM OLD.runtime_id THEN
    RAISE EXCEPTION 'stale control command lease is fenced' USING ERRCODE='23514';
   END IF;
  ELSIF NEW.status NOT IN ('succeeded','failed','unsupported','indeterminate') THEN
   RAISE EXCEPTION 'dispatched command requires proof or indeterminate state' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS server_bridge_control_fence_0285 ON server_bridge_control_commands_v3;
CREATE TRIGGER server_bridge_control_fence_0285 BEFORE UPDATE
ON server_bridge_control_commands_v3 FOR EACH ROW
EXECUTE FUNCTION server_bridge_control_fence_0285();

-- Efficient stale work discovery for operator views/recovery on a quiet node.
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_leased_timeout_0285
 ON server_bridge_control_commands_v3(lease_until) WHERE status='leased';
CREATE INDEX IF NOT EXISTS idx_server_bridge_control_pending_timeout_0285
 ON server_bridge_control_commands_v3(expires_at) WHERE status='pending';
