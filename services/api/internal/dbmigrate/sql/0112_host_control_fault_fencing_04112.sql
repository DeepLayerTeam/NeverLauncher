-- Serialize both uncertain AND accepted (unverified) host operations.
-- Previously, an accepted but unverified operation could be bypassed with a
-- different idempotency key and run a second dangerous host command.
-- If pre-existing duplicates violate this invariant, fail migration closed;
-- operator must reconcile them before enabling the new release.
DROP INDEX IF EXISTS server_bridge_host_unresolved_0413;
CREATE UNIQUE INDEX server_bridge_host_unresolved_0413
    ON server_bridge_host_operations_0413(server_id)
    WHERE status IN ('indeterminate', 'accepted');

-- One RemoteControl node may be configured under several server IDs.
-- The host identity, not only a logical server ID, is a command fence.
CREATE UNIQUE INDEX server_bridge_host_remote_unresolved_04112
 ON server_bridge_host_operations_0413(remote_node_id)
 WHERE status IN ('indeterminate', 'accepted');
