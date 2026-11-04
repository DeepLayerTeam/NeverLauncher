# ServerBridge network operations in Admin (0.41.11)

Admin → project → ServerBridge provides a live overview, network admission controls,
game commands, signed command ACKs, and a separate **Host Supervisor / JVM** panel.
The new host panel is wired to the **existing real** Backend → pinned RemoteControl
TLS → Host Supervisor / OS-JVM path; it never runs shell commands in the browser.

## Deployment

- Apply the existing PostgreSQL migration `0111_server_bridge_host_operations_0413.sql`
  before deploying the Backend. A PostgreSQL-backed ServerBridge is mandatory.
- Configure `LAUNCHER_SERVER_BRIDGE_HOST_TARGETS_FILE` with explicitly provisioned
  node IDs, pinned TLS root CA and private credentials readable only by Backend.
  There is no caller-selected host URL and no fallback to an untrusted endpoint.
- Provision and start a RemoteControl agent and Host Supervisor for each managed node.
- Grant **global** `host:process` to trusted operators. Project-scoped `gameserver:*`
  or `serverbridge:control` does not confer host process permissions. Every host
  mutation requires fresh MFA enforced on the Backend (not only in Admin).
- Deploy Admin and Backend of the same version and restart Admin to load the new UI.

## Real operation flow

1. Select an existing registered ServerBridge node. A live read-only RemoteControl
   status checks the actual supervisor and JVM state; a separate signed game
   heartbeat determines game readiness.
2. Select **Start JVM**, **Stop JVM**, or **Restart JVM**. The Admin asks for
   confirmation and persists an idempotency key in session storage **before** POST.
3. Backend persists an intent in PostgreSQL before calling RemoteControl once.
   RemoteControl returns a durable receipt; Backend verifies the host process and
   server heartbeat before marking a result `succeeded`. `accepted` is not success.
4. Refresh status or watch the automatically refreshed operation history. An
   `accepted` operation is reconciled via a read-only Backend GET with
   `refresh=1`; no host action is dispatched from GET.
5. A network error after POST is **indeterminate** until the original record is
   recovered. The UI offers retry of the **same** action and key, not a new key.
   Backend returns the prior journal record without executing the action again.
   An `indeterminate` journal entry blocks new operations on that host.

If the host status or durable journal cannot be read, the UI disables new host
mutations and shows **unknown**, not **stopped**, **healthy**, or **success**.
History is loaded from PostgreSQL, not from local browser storage; session
storage only keeps the exact unresolved HTTP request for safe recovery.

## Existing controls

- `server.save`, whitelisting, bans, moderation, maintenance/drain, broadcasts,
  and allowlisted console commands use signed ServerBridge commands; result
  statuses distinguish accepted, executed, verified, failed and indeterminate.
- Admission capacity updates require an expected routing revision and the UI
  checks both the API result and a fresh PostgreSQL overview before claiming
  that the policy was applied.
- Topology, routing state, node health, JVM/game telemetry and command history
  remain available in the same project-scoped workspace.
- **World backup/restore in 0.41.10 remains a host CLI operation**, not an
  HTTP/RemoteControl operation. The platform Backup/Restore screen handles
  Backend data, not Minecraft worlds. Do not label it a world backup or invoke
  unaudited host shell commands from the web interface.

## Test coverage and limits

`node --experimental-strip-types --test apps/admin/tests/*.test.mjs` covers
API clients, original-key replay, global host RBAC and freshness semantics. It
cannot certify the RemoteControl integration or JVM runtime on a live host.
Full Go Backend tests, a production Admin build with locked dependencies,
PostgreSQL transactions, and an end-to-end RemoteControl + real JVM/agent test
must pass on deployment infrastructure before production certification.
