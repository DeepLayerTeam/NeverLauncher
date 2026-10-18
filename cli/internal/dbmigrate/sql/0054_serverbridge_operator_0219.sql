-- ServerBridge Operations 0.21.9: grant existing scoped operator roles only the
-- signed, allowlisted control plane; console remains a separate privilege.
UPDATE roles
SET permissions = CASE
    WHEN permissions ? 'serverbridge:control' THEN permissions
    ELSE permissions || '["serverbridge:control"]'::jsonb
END
WHERE id = 'operator';
