-- 0.41.1: distinguish agent acceptance, invocation, and observed postcondition.
-- Keep historical successful rows untouched; no retrospective claim of verification.
ALTER TABLE server_bridge_control_commands_v3
 DROP CONSTRAINT IF EXISTS server_bridge_control_commands_v3_status_check;
ALTER TABLE server_bridge_control_commands_v3
 ADD CONSTRAINT server_bridge_control_commands_v3_status_check CHECK (
  status IN ('pending','leased','accepted','executed','succeeded','failed','unsupported','indeterminate','expired')
 );

CREATE OR REPLACE FUNCTION server_bridge_control_fence_0285() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('accepted','executed','succeeded','failed','unsupported','indeterminate','expired') THEN
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
  ELSIF NEW.status NOT IN ('accepted','executed','succeeded','failed','unsupported','indeterminate') THEN
   RAISE EXCEPTION 'dispatched command requires a receipt or indeterminate state' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
