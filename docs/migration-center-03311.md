# 0.33.11 — MIG11: Staged Cutover (Gravit → Never)

## Executable scope and operating contract

This release switches the **real PostgreSQL `channel_heads` delivery pointer** for one `(project, profile, channel)` at a time. The normal manifest API reads this pointer. Other project/profile/channel tuples are unaffected. The `0098` database migration installs a trigger on `channel_heads`: while a scope is `staged`, ordinary release publication for that scope fails closed. The activation transaction carries an exact run-scoped `SET LOCAL` marker, verifies its saved expected head revision, publishes the new pointer, records the external fencing reference and commits its event in **one transaction**. A retry after an uncertain commit must first GET the cutover list. An identical activation can be retried using the original request revision; changed evidence is rejected.

**Explicit limitation:** This does NOT stop the legacy Gravit LaunchServer, a game-world writer, a third-party auth database, external economy plugins, or the underlying network proxy. Those are *different writers* under the operator's control. The `X-Migration-Source-Fenced` header and SHA-256 evidence are **operator attestations**, not automatic proof. Until the old writer is truly stopped and verified externally, the ecosystem does not have a proven single-writer cutover. Never must not label it so. 0.33.12 must reconcile any post-switch changes before rollback.

## Preconditions enforced by Backend

- A prepared `gravit` migration run and current MIG03 source inventory.
- The **latest** MIG10 rehearsal is successful and no older than 2 hours. Missing/failed probes block cutover.
- MIG04 identities have no blockers; existing UUID owners match and new imported users exist with the expected UUID and name.
- MIG05 has no accounts requiring manual password reset; MIG06 security reset verified; MIG08 module analysis has no blockers.
- The selected release is `published`, belongs to a MIG07 workspace for this **exact run and profile**, and has an Ed25519 signature verified against the current Never manifest signing key.
- The expected revision of the live channel head matches the value provided at staging. Activation repeats checks; it also requires a freshly captured **source snapshot SHA-256 identical to the source snapshot in MIG10**. An operator-provided digest is not independently produced by Never.
- Fresh MFA, project-level `settings:manage`, exact run ID confirmation and server audit events.

## Operator procedure

1. Finish MIG01–MIG10 in a disposable/isolated environment; inspect the Migration Center report and confirm real `login`/`join` results, UUID/world/inventory/economy/plugin data. Publish a signed Never release for the MIG07 workspace.
2. Read the release channel head revision using existing Admin/manifest capabilities. Then stage one profile/channel:

```bash
nl migrate gravit cutover-stage --backend https://never.example --token "$ADMIN_TOKEN" \
  --run "$RUN" --confirm "$RUN" --profile-id client --channel stable \
  --release-id "$RELEASE" --head-revision 7 --stage-id "$REHEARSAL_STAGE"
```

3. Verify that ordinary Never publication to this scope is now rejected, and that the live manifest still points at the baseline release. Stage other profiles/channels separately as needed (canaries first).
4. **Outside of Never** stop/fence the legacy Gravit writer, quiesce database/world/economy/plugin writers, verify no old writer remains, and capture a current source snapshot using the same canonical snapshot format as MIG10. Retain immutable evidence outside the application and calculate its SHA-256. Observe client/server health and routing.
5. Activate, providing the receipt revision returned by staging (normally `1`), the independently captured snapshot digest and evidence reference:

```bash
nl migrate gravit cutover-activate --backend https://never.example --token "$ADMIN_TOKEN" \
  --run "$RUN" --confirm "$RUN" --profile-id client --channel stable \
  --expected-revision 1 --source-fenced true \
  --fence-reference ops/fence-ticket-42 --fence-sha256 "$EVIDENCE_SHA256" \
  --source-snapshot-sha256 "$CURRENT_SOURCE_SNAPSHOT_SHA256"
```

6. GET state (`cutover-list`) and verify the new `channel_heads.release_id` and incremented revision through API. Run live login/join/canary monitoring. There is **no automatic world rollback** in 0.33.11.

`cutover-cancel` unfreezes a scope that has **not** been activated. A cancelled scope retains its immutable record: create a new project/migration scope only through an explicit later workflow. Active release pointers are never blindly restored by this command. Avoid running old Backend binaries against a database with the MIG11 trigger.

## Validation

Run `go test -race -count=1 ./internal/gravitcutover` and the PostgreSQL `TestMigrationCutoverPostgres03311` on PostgreSQL 17, along with full Backend/API, CLI and React builds. Integration tests include stale head revision, publication fence, activation with wrong snapshot, verified activation, idempotency, live pointer readback and post-activation cancellation rejection. **Integration/E2E and live Gravit writer shutdown are not certified merely because this code was added.**
