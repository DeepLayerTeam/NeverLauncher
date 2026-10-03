# NeverLauncher 0.19.3 — Public ServerBridge Matrix

> Capability matrix. Runtime PASS evidence is produced by CI; the Bukkit row is intentionally marked build-compatibility because the release CI does not redistribute a CraftBukkit runtime.

| Platform | Family | Role | Minecraft | Coverage | Protocol | Zero-patch | Node identity | One-time join | Handoff | Telemetry |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| `velocity` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source  players + JVM |
| `bungeecord` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source  players + JVM |
| `waterfall` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | source  players + JVM |
| `bukkit` | `bukkit` | `backend` | `1.21.1` | `build-compatibility` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `spigot` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `paper` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `purpur` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `folia` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds; region-safe counters |
| `fabric` | `fabric` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `forge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |
| `neoforge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 (v2 rolling) | yes | Ed25519 | yes | target  TPS/MSPT + players + worlds + bounded chunks/entities |

Runtime status is not hard-coded into this document; CI evidence is attached to the exact commit/run.
