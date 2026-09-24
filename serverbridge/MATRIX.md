# NeverLauncher 0.14.9 — Public ServerBridge Matrix

> Capability matrix. Runtime PASS evidence is produced by CI; the Bukkit row is intentionally marked build-compatibility because the release CI does not redistribute a CraftBukkit runtime.

| Platform | Family | Role | Minecraft | Coverage | Protocol | Zero-patch | Node identity | One-time join | Handoff |
|---|---|---|---|---|---:|---:|---:|---:|---:|
| `velocity` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | source |
| `bungeecord` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | source |
| `waterfall` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | source |
| `bukkit` | `bukkit` | `backend` | `1.21.1` | `build-compatibility` | 2 | yes | Ed25519 | yes | target |
| `spigot` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `paper` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `purpur` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `folia` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `fabric` | `fabric` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `forge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |
| `neoforge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 2 | yes | Ed25519 | yes | target |

Runtime status is not hard-coded into this document; CI evidence is attached to the exact commit/run.
