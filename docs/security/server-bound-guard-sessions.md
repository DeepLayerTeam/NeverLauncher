# 0.50.7 — сеансы Guard, привязанные к серверу

## работающая реализация

The protected mode uses the existing signed Ed25519 ServerBridge Protocol v3 heartbeat, device-signed and one-use **continuous Windows Guard v2** attestation, hardware-key-signed exact component plan, PostgreSQL player-session authority, and correlated, runtime-bound `player.kick` controls. The code is executed on the actual HTTP admission, ServerBridge join validation and signed server heartbeat paths; there is no standalone mock attestation endpoint.

1. Enable **PostgreSQL** (including migration `0116_server_bound_guard_sessions_0507.sql`). A memory-backed ServerBridge is not accepted for protected admission.
2. Configure the existing Guard v2 release allowlist and runtime allowlist for your deployed platform, including the verified 0.50.7 launcher and Guard hashes. Existing release hashes from 0.50.6 do not authorize new bytes.
3. Provision the signed ServerBridge component plan policy using `LAUNCHER_SERVERBRIDGE_REQUIRE_PLAN_POLICY=1`, `LAUNCHER_SERVERBRIDGE_PLAN_POLICY_FILE=/secure/path/signed-policy.json`, and `LAUNCHER_SERVERBRIDGE_PLAN_POLICY_PUBLIC_KEY=<pinned-ed25519-key-hex>`. The signing key must remain offline. The policy must explicitly permit each exact (server, project, profile, channel, release signature, catalog SHA-256, plan SHA-256) tuple.
4. Upgrade ServerBridge runtime plugins to signed **Protocol v3** with runtime identity and authenticated node heartbeats. v2 and missing runtime identities are rejected when protected policy is enabled.
5. Permit the launcher to obtain both its one-use verified Guard ticket and its device-signed, one-use exact-plan challenge. During `sessionJoin`, the backend verifies both before creating an immutable per-player Guard binding, and rejects issuance if the durable insert fails.
6. The ServerBridge node redeems the join with its signed authenticated request. The backend compares the persisted account, Never session, Minecraft session, trusted device, key epoch, server, UUID, profile and build against the admission record, and rechecks current trust, attestation, allowed Guard artifacts, Guard runtime profiles and signed plan. For cross-server handoffs, the destination must be separately allowlisted for those exact build bytes.
7. Each accepted signed ServerBridge node heartbeat checks due protected player sessions against current authoritative PostgreSQL state and policy. When revoked or mismatched, the player session is atomically invalidated and a correlation-bound `player.kick` is queued for the running proxy/backend; the execution adapter must be running and polling the control queue.

## операции и ограничения

- An active player without an immutable Guard binding is not grandfathered into protected mode: the next node heartbeat queues a correlated disconnect.
- Rechecks are driven by actual node heartbeats and batched at up to 32 active sessions per server heartbeat; due records are at least 10 seconds old. Configure bridge heartbeat frequency and test worst-case queuing latency at your player count. **Do not treat 10 seconds as a guarantee for every player.** If the bridge or database becomes unavailable, automatic in-game revocation cannot be delivered, although protected admission/heartbeat responses fail closed.
- Revocation checks use the latest authenticated client evidence already issued. **They do not constitute fresh memory or runtime measurements from the running client.** The client watchdog introduced in 0.50.6 continues to enforce local integrity. A future client-to-server nonce/heartbeat protocol is required for cryptographically fresh remote client measurements.
- The continuous Guard runtime policy verification currently requires Windows user-mode Guard. This implementation does not certify Linux/macOS parity or real gameplay on those systems.
- A trusted Java extension has full process privileges. Signed evidence cannot prove that a compromised player host is cheat-free.
- Policies and revocations can force existing sessions off; never weaken checks to avoid reconnects. PostgreSQL/Guard failures should alert operators. Tune indexing and batch sizes only with measured throughput and authoritative correlation data.

## команды настоящих тестов

```sh
cd services/api
export LAUNCHER_TEST_POSTGRES_DSN='postgres://user:password@127.0.0.1:5432/disposable_db?sslmode=disable'
go build ./cmd/...
go test -race -count=1 ./internal/httpapi -run '^TestGuardBoundSession0507'
go test -race -count=1 ./internal/repository -run '^TestServerBoundGuardPostgres0507$'
```

The PostgreSQL integration case boots the full migration catalog, inserts a real active player and proxy runtime, persists an immutable Guard join, rejects replay, lists the real joined player, paces rechecks, revokes the session and asserts exactly one queued `player.kick` referencing the same correlation ID. Migration 0116 also upgrades the existing PostgreSQL-wide session-revocation trigger to include the same correlation in its queued JSON payload and preserve deduplication with the application-level revocation code. The CI workflow also compiles the API and CLI. These checks **do not** replace independent live Minecraft/Windows/HA acceptance on the final signed assets. Production GA remains blocked until that evidence exists.
