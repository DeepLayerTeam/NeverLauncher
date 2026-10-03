# NeverLauncher 0.19.5 — Public ServerBridge Matrix

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
