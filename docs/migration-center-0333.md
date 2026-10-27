# 0.33.3 — Gravit Source Inventory & Export (MIG03)

0.33.3 inventories an actual ZIP containing GravitLauncher source installation
files and produces a self-contained, deterministic, verified ZIP containing the
same file bytes plus `.never-migration/inventory.json`. It is not an account
import, UUID reconciliation, release signing, migration rehearsal or cutover.

## Requirements and sequence

1. Apply API PostgreSQL migration `0091_gravit_inventory_0333.sql` using the
   repository's normal migration workflow. Use an account with `settings:manage`.
2. Create a run and execute the 0.33.1 Never target baseline until
   `status=prepared,step=source_assessment`.
3. Generate an offline Gravit source ZIP under the owner's control. Include
   `LaunchServer.json`, `profiles`, `runtime`, `modules`, `ServerWrapper`,
   libraries, client data, assets and texture folders as needed. The source ZIP
   can contain credentials; use encrypted storage and HTTPS to the Backend.
4. Optionally assess compatibility with `nl migrate gravit assess` for sources
   under the original 64 MiB detector limit. Assessment and inventory must use
   the **same identical source bytes** when both reports exist.
5. Run inventory and export using the original ZIP again:

```sh
nl migrate gravit inventory --backend https://example.org --token "$NEVERLAUNCHER_TOKEN" \
  --run RUN_ID --source /secure/gravit-source.zip --output /secure/inventory.json
nl migrate gravit inventory --backend https://example.org --token "$NEVERLAUNCHER_TOKEN" --run RUN_ID
nl migrate gravit export --backend https://example.org --token "$NEVERLAUNCHER_TOKEN" \
  --run RUN_ID --source /secure/gravit-source.zip --output /secure/gravit-verified.zip
```

`--output` on export is required; the target **must not exist**. The CLI writes
through a mode-0600 temporary file, verifies the complete downloaded ZIP (CRC,
file length, every SHA-256 and embedded manifest SHA-256), and atomically
publishes it without replacing older copies. Server-side export is streamed,
so disconnected clients must retry with the identical source input.

Admin SPA and Embedded Admin offer the same upload, inventory, and export
operations. Browser downloads are not an alternative to a CLI-file-level
verification for very large archives.

## Limits, integrity and security

- Maximum uploaded compressed ZIP: **512 MiB**, at most **30,000 ZIP entries**,
  maximum declared uncompressed sum **2 GiB**, and at most **2 MiB** per parsed
  JSON config. Very large projects must be split into bounded, operator-managed
  source archives in a future workflow; splitting is not performed in 0.33.3.
- The scanner streams actual uncompressed bytes, validates ZIP CRC, size and
  SHA-256, detects unsafe/duplicate paths, rejects encrypted/special members,
  excessive expansion ratios and invalid/ambiguous critical JSON.
- The inventory includes per-file path, size, kind and checksum; counts of
  clients/assets/libraries, profiles, custom modules, auth provider types,
  texture provider types, optional action types, referenced servers and keys.
  It includes no source config values, passwords, private keys or raw ZIP bytes.
- The database stores only sanitized inventory JSON and SHA-256; committed
  changes are event-journaled. Idempotent repeats do not duplicate an event.
  The source ZIP is spooled to a **private mode-0600 temporary file (immediately unlinked on Unix)** for each
  request, then removed; no source content is persisted in SQL or as a
  long-lived server artifact.
- Export copies **the original bytes**, including sensitive configs, keys and
  passwords. Its embedded canonical JSON manifest makes every member
  independently verifiable; export is not encrypted or signed by Never.
  Protect transport, local download and backups accordingly; do not publish.
- If a compatibility report is already saved for the run, inventory must match
  its source SHA-256. After inventory, changing compatibility to another source
  is rejected. A different inventory upload may create a new revision **only
  when no compatibility report pins the source**.
- A successful inventory or export **does not** grant cutover readiness. User,
  UUID, worlds, runtime secrets and modules are not imported or executed.

## Tests

`go test -race ./internal/gravitinventory` covers roundtrip, deterministic
export, tamper/CRC rejection, duplicate paths, path traversal, invalid JSON,
source changes and temporary-file permissions. Separate CLI tests exercise
HTTP upload, verified download and overwrite prevention. PostgreSQL integration
tests cover idempotency, durable reports, source pinning and journaling. The
release CI builds the API with Go 1.27.3 and React Admin with Node 22. Passing
those tests and a real operator trial is necessary before production GA.
