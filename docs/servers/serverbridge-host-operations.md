# 0.41.3: Backend → RemoteControl → Host Supervisor

This is the **live** host lifecycle path. ServerBridge Java game commands and host
process commands have deliberately separate authorization domains. Backend does
not embed SSH or run arbitrary remote shells.

## Provision a real host

1. Configure an installed game server using `nl server-bridge host configure ...`.
   `nl server-bridge host status --server-root /srv/minecraft/survival` must report
   the configured Java process. Ensure the game adapter is enrolled in Backend
   as ServerBridge node `survival` for the same server root.
2. On the host, initialize the RemoteControl identity:
   `nl server-bridge host remote init --server-root /srv/minecraft/survival`.
3. Issue a **short-lived** service token for the Backend source address:
   `nl server-bridge host remote issue --server-root /srv/minecraft/survival --subject backend-control --scope host.status --scope host.start --scope host.stop --scope host.restart --source 10.10.0.5/32 --ttl-seconds 900 --token-file /etc/launcher/host-survival.token`.
   Re-issue tokens as they expire and atomically update the private token file.
   Never commit the token or TLS private keys to source control.
4. Start the agent with a trusted TLS certificate:
   `nl server-bridge host remote serve --server-root /srv/minecraft/survival --listen 10.10.0.21:9443 --tls-cert /etc/launcher/host.crt --tls-key /etc/launcher/host.key --allow-source 10.10.0.5/32`.
   Use `--client-ca` to enforce mutual TLS in production, and provision the
   corresponding Backend client certificate. The RemoteControl key and host
   journal remain private to that server root.
5. On Backend, create an owner-readable **0600** JSON file at an absolute path:

```json
{
  "survival": {
    "url": "https://10.10.0.21:9443",
    "nodeId": "<RemoteControl nodeId from remote init>",
    "caFile": "/etc/launcher/remote-ca.pem",
    "tokenFile": "/etc/launcher/host-survival.token",
    "clientCert": "/etc/launcher/backend.crt",
    "clientKey": "/etc/launcher/backend.key"
  }
}
```

Every referenced file must have absolute path, be regular, non-symlink and
private to its owner (0600). Point
`LAUNCHER_SERVER_BRIDGE_HOST_TARGETS_FILE` to this registry. Backend TLS
requires TLS 1.3 and verifies the host's CA, hostname/IP and RemoteControl
node identity. Outbound proxies and redirects are disabled.

Apply migration `0111_server_bridge_host_operations_0413.sql` through the normal
Backend/CLI migration runner. Host process operations are disabled outside the
PostgreSQL deployment mode. An account requires GLOBAL `host:process`, project
visibility and a fresh MFA assertion. A project owner with game-server controls
alone **cannot** start or stop a physical host.

## Real API invocation

```sh
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer <authenticated-admin-access-token>' \
  -H 'Idempotency-Key: host-survival-start-20261030' \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}' \
  'https://backend.example/api/v1/server-bridge/servers/survival/host/operations'
```

Save `data.operation.id` from the response. Use the *same* key for repeats of
that exact user intent; never generate a new key to work around `indeterminate`.
Check state without re-executing the command:

```
GET /api/v1/server-bridge/servers/survival/host/operations/{operationId}
GET /api/v1/server-bridge/servers/survival/host/operations/{operationId}?refresh=1
```

`refresh=1` re-reads the host's OS process state and ServerBridge's runtime
identity, but never sends a POST to RemoteControl. `succeeded` requires an
agent-persisted `succeeded` receipt, an independently read matching live
Supervisor/JVM state, and (for start/restart) a newer ServerBridge heartbeat
from a new runtime. While the Java process is healthy but its bridge adapter
has not registered, the state remains `accepted`.

When a backend or host crashes in the uncertain window, the journal retains
`indeterminate`. A different key is blocked for that server until an operator
inspects the durable Backend operation and host RemoteControl journal using
`nl server-bridge host remote inspect --server-root ... --idempotency-key nl-host-<operationId>`.
No automated command replay, lease-based re-dispatch, or claim of a verified
success is allowed in this release. Operational recovery from a genuinely
unknown outcome requires a separately audited manual procedure.

## Boundary and known limitations

- A successful host restart is not the same as Minecraft application readiness;
  ServerBridge must report a fresh, different runtime identity. Vanilla servers
  without an enrolled ServerBridge agent cannot be marked end-to-end verified.
- A RemoteControl token expires after at most 15 minutes; rotate it before
  expiry via the operator's secret distribution mechanism.
- There is no shell/JVM-argument execution exposed by these endpoints.
- HTTP receipt delivery, PostgreSQL commit, real Java process and real plugin
  activation must all be exercised in the deployment's own staging E2E before
  calling this a production-certified configuration.
