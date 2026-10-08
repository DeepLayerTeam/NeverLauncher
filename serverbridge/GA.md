# ServerBridge 3 GA — NeverLauncher 0.20.0

ServerBridge 3 is GA in NeverLauncher 0.20.0. Protocol v3 is frozen: the canonical feature-set digest is `098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc`. Protocol v2 remains accepted by Backend only as `compatibility-deprecated`; new 0.20.0 bridges negotiate v3 only.

## Production migration v2 → v3

1. Apply database migration `0041_serverbridge3_ga_0200` with `nl db migrate apply`, then verify it with `nl db migrate verify`.
2. Keep the 0.20.0 Backend healthy and verify `GET /api/v1/server-bridge/capabilities` reports `protocolV3Frozen=true`, `protocolV3Status=ga-frozen` and the frozen digest above.
3. For every managed node run `nl server-bridge migrate-v3 --server-dir <dir> --artifacts-dir <release-artifacts>`. The command performs the normal certified transactional upgrade, preserves the Ed25519 node identity, supports `--dry-run`, and records `.neverlauncher/server-bridge/protocol-v3-ga-migration.json` after success.
4. Restart the Minecraft/proxy process when reported by the installer. Confirm the node appears as Protocol v3 in `GET /api/v1/server-bridge/overview`.
5. Keep Protocol v2 only for remaining legacy nodes. v2 responses carry deprecation/migration headers and the Admin UI counts nodes still requiring migration.

The migration does not patch Minecraft/authlib/core. Rollback remains the existing `nl server-bridge rollback` path and restores the previous managed bridge artifact/state while preserving the node identity.

## Certification and installation

A GA release is valid only when `SERVERBRIDGE3_CERTIFICATION.json` has schema `1.1`, `ga=true`, `protocolV3Frozen=true`, the exact frozen feature digest, `protocolV2Mode=compatibility-deprecated`, `installerUpgradePath=true`, `unifiedOperatorAPI=/api/v1/server-bridge/overview`, and hashes for all 14 supported artifacts. `BRIDGE_RELEASE_ALLOWLIST.json` remains schema `3.0` and carries the same GA protocol policy plus the security profile and exact per-platform SHA-256 values.

`nl server-bridge install`, `upgrade`, and `migrate-v3` reject a 0.20.x artifact whose certification/allowlist does not satisfy this GA boundary unless the explicit development-only unverified override is used.

## Operator API and Admin UI

`GET /api/v1/server-bridge/overview` is the single authenticated operator view for topology, control history, latest telemetry, node/runtime state, Protocol v2 migration status, upgrade recommendations, and ServerBridge audit events. The Admin UI consumes this endpoint directly.

The public compatibility matrix is `GET /api/v1/server-bridge/matrix` and `serverbridge/MATRIX.md`. It lists all 14 release targets and explicitly marks Protocol v3 as GA/frozen and Protocol v2 as compatibility/deprecated.
