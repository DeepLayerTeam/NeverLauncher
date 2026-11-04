# 0.41.12 — ServerBridge host command fault handling (operations)

This release changes the **executable RemoteControl listener, Backend host-operation reconciliation and PostgreSQL unique fences**. It does not claim to make arbitrary Minecraft commands exactly-once; uncertain effects remain intentionally unrepeatable without operator investigation.

## Invariants

1. Backend commits a PostgreSQL intent before issuing a host command. Replaying the same idempotency key returns its original journal entry, never a second POST.
2. Both `indeterminate` and `accepted` (host/game not yet verified) operations block **new** keys for the logical server and the physical `remote_node_id`. Migration `0112` enforces both in PostgreSQL; duplicate older unresolved operations will cause migration to fail closed rather than silently discard one.
3. RemoteControl writes the `indeterminate` receipt before invoking the Host Supervisor. A new command with another key is refused if *any* prior receipt is indeterminate. Corrupt/missing journal access fails closed. Only replay of the original key returns the original receipt.
4. The listener holds an OS-enforced kernel lock for its lifetime. On Unix, `agent.fence` is flock-locked; on Windows, it is locked with `LockFileEx`. A competing listener cannot steal the lock even if the old `agent.lock` metadata belongs to a dead process. Do not delete or replace the persistent `agent.fence` inode on a live machine.
5. Recovery of a lost ACK uses an **authenticated read-only GET** `/v1/host/receipts/{originalWireKey}`. It checks the caller's original subject and both status/action permissions. Backend verifies the receipt's action/key hash, reads live Host Supervisor process state, and requires a newly fresh ServerBridge heartbeat before marking `start` or `restart` successful. This path never dispatches the command again.
6. A timeout, lost receipt, agent crash with `indeterminate` receipt, corrupt journal, unverified host process, stale heartbeat, or missing PostgreSQL does **not** authorize another physical action. New commands remain blocked while the outcome is unresolved; this is intentional and requires supervised incident reconciliation.

## Test reproduction

```bash
scripts/test/serverbridge-host-faults-04112.sh
```

This runs race-checked RemoteControl tests (timeout/lost ACK, concurrent callers with distinct keys, agent restart, journal corruption, stale lock split-brain), actual OpenJDK 21 JVM lifecycle regression (stop/restart/crash/backoff), and race-checked isolated Backend TLS client tests. Local Windows cross-compile is separate; actual Windows runtime testing is required before Windows production certification.

## Upgrade / recovery

- Back up PostgreSQL and the private Host Supervisor/RemoteControl state **without discarding** `remote/commands` receipts or the backend operation journal. Apply migration `0112` **before** accepting new requests.
- If migration detects two prior accepted/unresolved operations for the same physical host, keep control disabled and investigate both receipts and actual host/game state before resolving the conflict. Do not disable the unique indexes to force a rollout.
- After a lost HTTP response, use the **original operation ID** from Admin and perform `GET operation?refresh=1`; this only reads the remote receipt and live host state. If the remote receipt is not durable or the host identity is uncertain, the result remains `indeterminate`.
- For unresolved action effects, halt automated orchestration. Inspect the original receipt locally with `nl server-bridge host remote inspect --server-root <root> --idempotency-key <wire-key>`, verify the actual JVM/host/game state, and follow incident recovery. **Never delete/modify command receipts or change PostgreSQL status solely to unblock a retry.**
- The remote journal scan is deliberately fail-closed. Retention and human reconciliation of permanently indeterminate commands require an explicitly audited operational procedure; no unsafe automatic expiry or release was added.

## Verification boundary

The script exercises real Java processes, but not actual Paper/Fabric/Velocity Minecraft distributions. PostgreSQL integration and full Backend tests require a working PostgreSQL service and the specified Go toolchain (Go 1.27.3). These checks are still necessary for production release certification.
