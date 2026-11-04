-- 0.28.1 Explicitly split game operations from Backend and Host. No blanket
-- migration of arbitrary custom roles. Only canonical admin/operator that
-- previously held ServerBridge control receive equivalent *game* privileges.
-- Backend/Host/host:exec are never automatically granted by this migration.
UPDATE roles SET permissions = (SELECT jsonb_agg(DISTINCT value) FROM jsonb_array_elements_text(permissions || '["gameserver:broadcast","gameserver:moderate","gameserver:save","gameserver:traffic","gameserver:shutdown","gameserver:console"]'::jsonb) AS p(value))
WHERE id = 'admin' AND permissions ? 'serverbridge:control'
;
UPDATE roles SET permissions = (SELECT jsonb_agg(DISTINCT value) FROM jsonb_array_elements_text(permissions || '["gameserver:broadcast","gameserver:moderate","gameserver:save","gameserver:traffic"]'::jsonb) AS p(value))
WHERE id = 'operator' AND permissions ? 'serverbridge:control'
;
