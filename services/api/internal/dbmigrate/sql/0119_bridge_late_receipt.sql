-- Resolve a delivery made indeterminate by the repository, never by an agent.
-- Keep the original delivery identity and all other fields immutable.
ALTER TABLE server_bridge_control_commands_v3
 ADD COLUMN lease_reconciled boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION server_bridge_control_fence_0285() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='indeterminate' AND OLD.lease_reconciled AND NOT NEW.lease_reconciled AND OLD.result='{}'::jsonb
    AND COALESCE(OLD.lease_owner,'')<>'' AND COALESCE(OLD.lease_token,'')<>''
    AND OLD.error IN (
      'delivery lease expired without proof of completion',
      'Доставленная команда потеряла аренду или среду выполнения до подтверждения',
      'Срок действия доставленной команды истёк без подтверждения завершения',
      'Срок аренды доставки истёк без подтверждения завершения',
      'Доставка привязана к устаревшему идентификатору Runtime',
      'Доставленная команда утратила аренду или среду выполнения до подтверждения ACK',
      'Выданная команда потеряла аренду без подтверждения завершения')
    AND NEW.status IN ('accepted','executed','succeeded','failed','unsupported','indeterminate')
    AND NEW.lease_until IS NULL AND NEW.completed_at IS NOT NULL
    AND (to_jsonb(NEW) - ARRAY['status','result','error','completed_at','updated_at','lease_until','lease_reconciled'])
        = (to_jsonb(OLD) - ARRAY['status','result','error','completed_at','updated_at','lease_until','lease_reconciled'])
 THEN
  RETURN NEW;
 END IF;
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
