# NeverLauncher 0.20.0 — Public ServerBridge Matrix

> ServerBridge 3 GA compatibility matrix. Protocol v3 is frozen; Protocol v2 is compatibility/deprecation-only and must migrate with `nl server-bridge migrate-v3`. Runtime PASS evidence is produced by CI; Bukkit, Quilt and Sponge declare build-compatibility where CI cannot legally/practically redistribute a full target runtime; Vanilla is certified through the sidecar RCON harness.

| Platform | Family | Role | Minecraft | Coverage | Protocol | v2 compatibility | Zero-patch | Node identity | One-time join | Handoff |
|---|---|---|---|---|---:|---|---:|---:|---:|---:|
| `velocity` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | source |
| `bungeecord` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | source |
| `waterfall` | `proxy` | `proxy` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | source |
| `bukkit` | `bukkit` | `backend` | `1.21.1` | `build-compatibility` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `spigot` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `paper` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `purpur` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `folia` | `bukkit` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `fabric` | `fabric` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `quilt` | `quilt` | `backend` | `1.21.1` | `build-compatibility` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `forge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `neoforge` | `modloader` | `backend` | `1.21.1` | `runtime-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `sponge` | `sponge` | `backend` | `1.21.1` | `build-compatibility` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |
| `vanilla` | `vanilla-sidecar` | `backend` | `1.21.1` | `sidecar-rcon-e2e` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | target |

Runtime status is not hard-coded into this document; CI evidence is attached to the exact commit/run.
