# NeverLauncher 0.19.7 — Public ServerBridge Matrix

> Capability matrix. Runtime PASS evidence is produced by CI; the Bukkit row is intentionally marked build-compatibility because the release CI does not redistribute a CraftBukkit runtime.

| Platform | Family | Role | Minecraft | Coverage | Protocol | Zero-patch | Node identity | One-time join | Handoff | Telemetry | Ordered events |
|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
| `velocity` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source | players + JVM | lifecycle + login + connect/switch |
| `bungeecord` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source | players + JVM | lifecycle + login + connect/switch |
| `waterfall` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source | players + JVM | lifecycle + login + connect/switch |
| `bukkit` | `bukkit` | `backend` | `1.21.1` | `build-compatibility` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `spigot` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `paper` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `purpur` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `folia` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds; region-safe counters | lifecycle + player + world |
| `fabric` | `fabric` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `forge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |
| `neoforge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target | TPS/MSPT + players + worlds + bounded chunks/entities | lifecycle + player + world |

Runtime status is not hard-coded into this document; CI evidence is attached to the exact commit/run.


## 0.19.5 Control API

Все target-платформы используют Protocol v3 feature `control.secure-channel-v1`: signed node poll/ACK, Backend Ed25519 command signatures, runtime-bound leases, local idempotency journal и platform-native execution. OS shell execution не используется. Proxy cores честно возвращают `unsupported` для whitelist/ban/save, которыми они не управляют.


## 0.19.6 Topology & Routing 2

Protocol v3 feature `topology.routing-v2` publishes an Ed25519-attested, runtime-bound route snapshot on heartbeat. Proxy nodes receive only fresh `ready` backends with `healthy/degraded` health and available capacity. Maintenance, draining, unhealthy, stale and full nodes are excluded and rejected again during handoff redemption/direct join. Handoff v3 stores source+target runtime/routing proofs; v2 remains available for rolling upgrades. Stale learned edges are disabled and purged automatically.
## 0.19.7 Player Session Integration 3

Protocol v3 feature `session.player-lifecycle-v3` carries a backend-issued 256-bit correlation from launcher join through proxy handoff to backend admission. PostgreSQL enforces one active gameplay correlation per Never/Minecraft credential, records an ordered runtime-bound transfer chain and marks each transfer for Device Trust/Guard recheck before consume. Clone replacement and explicit/session/device invalidation fan out durable `player.kick` control commands to all currently bound proxy/backend runtimes. Protocol v2 remains available as the rolling-upgrade compatibility path without synthetic runtime/session proofs.

