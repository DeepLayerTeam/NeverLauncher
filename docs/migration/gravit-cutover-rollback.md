# Gravit → Never 0.44.8 — эксплуатационное переключение и откат

**Supported scope:** one migration run, one profile and one Never release channel at a time. Backend route changes require PostgreSQL and a signed/published Never release. No operation here modifies Gravit worlds, player inventories, plugins, proxy configuration, DNS, account stores or externally running Minecraft processes. Operators must freeze every independent writer, back up both systems and switch all external entry points themselves; the tool only fences the named systemd writer. A masked unit can still be bypassed by a separately launched process. Successful Go tests do not certify a real server cutover.

## Cutover

1. Finish the source inventory/import, identity and auth checks, module parity, ServerBridge enrollment and MIG10 live Minecraft rehearsal. Store backups and verify restoration separately. Get `runId`, the rehearsal `stageId`, source snapshot digest and target release ID.
2. Use `nl migrate gravit cutover-stage --backend https://HOST --token ... --run RUN --confirm RUN --profile-id PROFILE --channel stable --release-id RELEASE --stage-id STAGE --head-revision REV`. This stages the actual Never release route and fences ordinary channel publications. It does NOT stop Gravit or route players.
3. Arrange a maintenance window. Stop player entry and *all* external writers/proxies. On the **Gravit source host**, as an authorized systemd operator, run:

   ```sh
   nl migrate gravit fence-source --run RUN --confirm RUN --profile-id PROFILE --channel stable --stage-id STAGE --unit gravit-launchserver.service --output /var/tmp/gravit-stop-state.json
   ```

   It performs `systemctl mask --runtime --now UNIT`, checks `ActiveState=inactive` and `UnitFileState=masked[-runtime]` twice and durably writes a mode-0600 state file without replacing an existing one. On failure, do **not** automatically unmask the unit. Only a person with source-host privileges may unmask it after the migration outcome is decided.
4. **After** the stop, export a NEW source state JSON in the `gravitrehearsal.Snapshot` shape (world SHA-256, loader, optional preset SHA-256, players with UUID, inventory/permission/economy/skin hashes, admin flag). The export must be taken from a quiescent data source and have a filesystem modification time after the stop. All snapshot fields must reflect the real system; copying the rehearsal snapshot without independently exporting current state is prohibited.
5. Check the fresh export against the earlier MIG10 source snapshot digest:

   ```sh
   nl migrate gravit verify-source-fence --state /var/tmp/gravit-stop-state.json --snapshot /var/tmp/gravit-fresh-source.json --expected-snapshot-sha256 SHA256_FROM_MIG10 --output /var/tmp/gravit-fence-receipt.json
   ```

   The utility rechecks the masked/inactive unit before and after reading the snapshot, computes the typed snapshot digest, and writes a fresh SHA-256-addressable receipt. It prints `sourceFenceReference`, `sourceFenceEvidenceSha256`, and `currentSourceSnapshotSha256`. Retain the receipt alongside your maintenance logs. Evidence expires after ten minutes (source-stop state after fifteen minutes). Re-run the source verification after expiration; if the source stop state expires, conduct another stop check with a fresh state file.
6. Activate with the new `--fence-receipt` on a trusted administrative workstation:

   ```sh
   nl migrate gravit cutover-activate --backend https://HOST --token ... --run RUN --confirm RUN --profile-id PROFILE --channel stable --expected-revision ROUTE_REV --source-fenced true --fence-receipt /var/tmp/gravit-fence-receipt.json
   ```

   The backend independently binds the complete receipt to the staged run/profile/channel/stage, the source snapshot and its SHA-256, and revalidates MIG10, source inventory, identity, authorization, modules, signed release and the head revision before changing `channel_heads` inside a serializable transaction. The staging channel remains unchanged if any prerequisite fails. An admin can also paste the receipt JSON and its printed SHA-256 in Migration Center. A receipt is **not** a signature from systemd; it is operator-supplied proof and cannot attest other writers, separate JVMs or network cutovers.
7. Verify the delivered manifest and real Minecraft login/join through the production entry point, then independently switch DNS/proxy/traffic. Use `cutover-list` and the migration audit after any HTTP timeout; do not guess whether activation committed. The old Gravit source remains fenced until successful verification and the rollback window ends.

## Безопасный откат

1. Stop and independently verify all Never writers and real game servers, ensure the Gravit source is still fenced, and take a fresh Never world/player/permissions/economy snapshot from a consistent production backup. Verify backup restore independently. If player/world state changed since MIG10, reconcile data back into a separately fenced Gravit environment **before** a rollback. Do not restore stale snapshots over active worlds.
2. Run the existing `rollback-plan` with `--snapshot /absolute/path.json --evidence-reference ...`. The CLI now uses SHA-256 of the **exact exported snapshot JSON bytes** as `evidenceSha256` rather than accepting an arbitrary operator string. If `--evidence-sha256` is present it must equal that calculated hash. The backend compares semantic world and player contents against MIG10; reconciliation needs a separate evidence digest.
3. A fresh plan replaces the previous uncommitted approval under PostgreSQL project/run locks and invalidates its old plan hash. A ten-minute-old plan does **not** permanently block rollback. Obtain the returned `planSha256` and route revision; do not use a stale receipt.
4. Run `rollback-commit --snapshot THE_SAME_FRESH_JSON --plan-sha256 APPROVED --expected-revision REV --writer-fenced true --source-writer-fenced true ...`. CLI uses the bytes actually submitted to derive `currentEvidenceSha256`; the backend demands an exact match with the stored plan, unchanged snapshot contents, unchanged approved release, live route revision, both fencing confirmations, and (for `stable`) a new one-time certified stable release permit.
5. A successful transaction returns the prior Never channel head. It neither restarts Gravit nor transfers new world data. The prior Never release must still exist and pass signature/GA validation. If there was no previous stable release, automatic stable rollback is blocked; manual traffic recovery to the externally retained Gravit source must be planned separately.

**Recovery:** `cutover-cancel` only cancels a staged (not activated) route. An active route must use rollback and reconciliation. After a timeout, GET the stored route/plan/rollback state. `sourceFenceReceipt` is operator evidence, not a remote attestation, and physical access/compromised systemd or privileged independent writers are out of scope. Actual PG, Minecraft, Gravit/systemd host and proxy tests remain release requirements.
