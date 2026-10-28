# 0.33.12 — MIG12: Operational Rollback

## What actually rolls back

The implementation restores the **live Never PostgreSQL `channel_heads` pointer** to its exact pre-MIG11 release (or removes the head if absent), with an atomic CAS against the activated revision. It commits the rollback receipt and migration event in the **same serializable transaction**, protected by project/run/route row locks and a transaction-local writer token. Migration `0099` extends the MIG11 trigger so ordinary publishers **cannot overwrite or DELETE an active channel** before rollback. A completed rollback is immutable and replay-safe. An active channel that has changed its revision, release, version, or digest is not rolled back blindly.

**This is not automatic restoration of Minecraft world files, economy/permissions databases, third-party plugin data, Gravit auth or source writers.** Neither the backend nor CLI has access to validate the operator's network/OS fencing. Re-activation of Gravit, snapshot restore and merging post-cutover writes must be independently coordinated; the system does not grant success or restore an old snapshot over new data.

## Snapshot comparison and failure behavior

MIG12 requires an operator-produced **fresh source-of-truth snapshot of the live destination deployment, collected after externally stopping game/plugin and Never writers**. The JSON schema matches the `Snapshot` property from MIG10: `worldSha256`, `loader`, `optionalPresetSha256`, `players` (`sourceId`, `uuid`, `inventorySha256`, `permissionsSha256`, `economy` as decimal string, `skinSha256`, `admin`). Canonical generation requires the same exporters and normalizations used by MIG10. Export the world files and plugin databases with all writers stopped so digests are meaningful. Preserve the raw backing files and separately computed SHA-256 evidence; never include private keys in API requests.

The server re-evaluates the latest MIG10 report using the supplied current snapshot. Changes in world checksum, player count, UUID, inventory, economy, plugin permissions, skin, admin rights, loader or optional preset **block an unchanged-state rollback**. Legitimate post-cutover writes may be preserved if and only if the operator **first** reconciles/merges all relevant data into the previously fenced Gravit environment outside Never, then exports a new **reconciled source** snapshot. MIG12 uses the MIG10 validator to compare the live Never destination **against that freshly reconciled source**, including changed economies/worlds and added players. Both must match exactly. Without this independently supplied source snapshot, or if any domain differs, the server rejects the plan. The server never performs the external merge or overwrites a world snapshot itself. There is no `--force` or skip-validation option.

The rollback plan pins the current snapshot digest, a separate evidence reference/hash, exact MIG11 route revision and baseline digest. It is immutable and expires for commit after 10 minutes. Commit requires fresh MFA, both writers independently fenced, a freshly exported snapshot again (must hash to the same state), and an exact plan SHA-256. The application can verify its JSON and digests, **not that the external systems were actually fenced or the exported data are truthful**.

## Procedure

1. Stop/fence Never Launcher deployment/publishers and all game/world/plugin/SQL writers externally. Keep the source Gravit writer stopped. Confirm no writes are in progress. Export the *full current production data* using the existing MIG10 exporters, including UUID/world/economy/permissions. Retain evidence in immutable storage.
2. Determine the active route receipt revision from `nl migrate gravit cutover-list`. Save the snapshot in `/secure/current-snapshot.json`; calculate the SHA-256 of the independently retained evidence bundle, not of an arbitrarily typed status flag.
3. Request an actual server-side comparison:

```bash
nl migrate gravit rollback-plan --backend https://never.example --token "$ADMIN_TOKEN" \
  --run "$RUN" --confirm "$RUN" --profile-id client --channel stable \
  --expected-revision "$CUTOVER_REVISION" --never-writer-fenced true \
  --snapshot /secure/current-snapshot.json --evidence-reference ops/immutable-proof-42 \
  --evidence-sha256 "$EVIDENCE_SHA256"
```

4. Inspect `ready` and `blockers`. **Any blocker means stop**; do not overwrite worlds. For changed data, first merge post-switch updates into Gravit using your external world/plugin migration procedure. Capture a new **source** snapshot and an immutable reconciliation receipt, then re-run `rollback-plan` with `--reconciled-source-snapshot /secure/reconciled-gravit.json --reconciliation-evidence-sha256 "$RECONCILIATION_SHA256"`. The server validates full parity of the post-merge source and current Never destination; it does not treat a checkbox or a hash alone as proof. A previously saved conflicting plan cannot be replaced silently.
5. Independently recapture the current snapshot **after writers remain fenced**. It must still match the plan exactly. Commit within 10 minutes:

```bash
nl migrate gravit rollback-commit --backend https://never.example --token "$ADMIN_TOKEN" \
  --run "$RUN" --confirm "$RUN" --profile-id client --channel stable \
  --expected-revision "$CUTOVER_REVISION" --never-writer-fenced true \
  --source-writer-fenced true --plan-sha256 "$PLAN_SHA256" \
  --snapshot /secure/current-snapshot-fresh.json \
  --current-evidence-sha256 "$FRESH_EVIDENCE_SHA256"
```

For a plan with `mode=reconciled`, the **commit** must also pass `--reconciled-source-snapshot /secure/reconciled-gravit-fresh.json --reconciliation-evidence-sha256 "$RECONCILIATION_SHA256"`; the source digest must still match the saved plan.

6. Call `rollback-status` or Admin to verify `state=completed`, then read the actual Never channel head and check the original release ID or its absence, and complete a controlled external restoration plan if needed. **Never does not automatically start Gravit or transfer/merge gameplay changes**.

## Hard stops

- No successful MIG10, wrong stage/revision or altered head, changed world/player data, missing historical published release, an unsigned/changed baseline release or an invalid Never Ed25519 signature, expired/mismatched plan or missing operator fencing confirmations.
- `SET LOCAL` channel-head guard applies to `INSERT`, `UPDATE`, **and** `DELETE`; active stage cannot silently be published over while a rollback is being planned.
- Ordinary database snapshots are not restored over changed worlds. External writes are not cryptographically attested by Never: deploy OS/network/DB-level enforcement before using this operation for real production cutover/rollback.

## Verification

Run Go race/unit tests, the extended `TestMigrationCutoverPostgres03311` (covers MIG12 active writer fence, blocked economy changes, replay, stale evidence and real channel pointer reversal), HTTP/CLI compilation, the React production build, version synchronization and OpenAPI validation. CI workflow: `.github/workflows/gravit-operational-rollback-03312.yml`. Real Minecraft/world/plugin and actual Gravit writer fencing E2E must be tested independently; this code alone is not production certification of the full ecosystem.
