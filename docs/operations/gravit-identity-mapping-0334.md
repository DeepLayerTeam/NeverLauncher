# Launcher 0.33.4 — Identity & UUID Mapping (MIG04)

This release is an executable identity reconciliation step. It does **not** create users, transfer password hashes, accept legacy credentials or cut over servers. A `prepared` run is not a successful migration.

## Supported source layouts

Provide the exact same protected ZIP that was previously inventoried using MIG03:

- Gravit FileAuthSystem JSON at any path ending `FileAuthSystem/Database.json` or `FileAuth/Database.json` (case-insensitive, optional parent directories). This is the UUID-keyed map used by the upstream FileAuthSystem module. The file's password, permissions, roles, skin and cloak fields are discarded by the identity mapper. `Sessions.json` is  parsed as identity data.
- `sql-export/users.csv`, optionally under a parent directory. This is **not** a dump of SQL statements. It is a snapshot exported from the actual Gravit SQL users table, normalized to headers **`id,username,uuid`**, with an immutable, unique provider-local source ID. Extra columns, including password hashes, are ignored. Export the actual UUID from the game system: do not generate or recompute one using a nickname or the SQL row number. SQL column names can be customized in Gravit LaunchServer, so the administrator must map their configured SQL columns during export.

The ZIP may contain both layouts. Duplicates or collisions across the two are reported and blocked. Unknown custom auth stores or providers are not silently interpreted as supported.

## Operator workflow

```sh
nl migrate gravit create --backend https://.example --token "$TOKEN" --project my-project --key migration-ticket-42
nl migrate gravit execute --backend https://never.example --token "$TOKEN" --run RUN_ID
nl migrate gravit inventory --backend https://never.example --token "$TOKEN" --run RUN_ID --source /secure/gravit.zip
nl migrate gravit map-identities --backend https://never.example --token "$TOKEN" --run RUN_ID --source /secure/gravit.zip --output /secure/uuid-map.json
nl migrate gravit identities --backend https://never.example --token "$TOKEN" --run RUN_ID
nl migrate gravit verify-identities --backend https://never.example --token "$TOKEN" --run RUN_ID
```

For `map-identities`, the API checks the exact SHA-256 and size against the persisted MIG03 inventory, validates ZIP contents/CRC and confirms its inventory manifest hash. No trusted source-directory path or ZIP extraction destination is accepted on the Backend. HTTPS is required by the CLI except explicit IP loopback.

## Result meanings

- `matched`: source UUID **and** case-insensitive Minecraft username match one existing Never user. The target user ID is stored as a reference only, and its ownership must be verified again after auth import and before any cutover.
- `pending_import`: no existing Never user has that UUID/name. Mapping is persisted for subsequent authenticated account import (MIG05); **no account is created** by MIG04.
- `blocked`: duplicate source ID/UUID/name, conflicting or ambiguous Never target UUID/name or unsupported source content. Such entries must not proceed automatically to cutover. UUIDs are never reassigned simply to resolve a conflict.

`ready=true` is a narrow identity-map condition: every row currently matches an existing target. **It is not authorization to migrate passwords, move inventory/world data, import modules, deploy or cut over.** Reverification compares stored IDs against the live Never profile and official identity tables and emits a new audit event only when results change.

## Safety and consistency

PostgreSQL tables `migration_identity_snapshots_0334` and `migration_identity_rows_0334` retain the source UUID mapping and cleaned status. Raw credential hashes, user sessions, tokens, keys and source files do not enter these tables. The first accepted account set is pinned by a SHA-256 digest. Sending a different account set under the same run returns a conflict instead of overwriting a reviewed identity map. A new project source requires a separate migration run and re-inventory.

MIG04 never merges accounts by email or nickname, cannot reset established immutable Never UUIDs, and does not modify Minecraft profiles. Run `verify-identities` after any import or change to the target identity store. Full file migration, authorized account creation/password carryover, staged cutover and operational rollback remain later milestones.

For projects on older, nonstandard or third-party Gravit modules and for SQL snapshots with unknown UUID semantics, treat compatibility as unverified until the corresponding provider has an explicit tested adapter. Use a secured workstation and protected directories when generating SQL CSV or storing source ZIPs.
