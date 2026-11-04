# NeverLauncher 0.45.0 — Migration GA: operational procedure and limits

**Status:** source implementation and verification tools. The existence of version 0.45.0 is **not** proof that the production Migration GA criteria have passed. Certification requires independently observed, real Gravit/Minecraft migration of all three reference classes and retained evidence. In the absence of that infrastructure the outcome is `BLOCKED`.

## область действия

Migration GA requires three different Gravit source projects with independent migration run IDs: `fileauth-single`, `sql-modded` (Forge and NeoForge), and `proxy-network`. The existing full 36-check matrix, actual player login/join, negative authorization, optional conflicts, module substitution, live ServerBridge, cutover and rollback drills are mandatory. The GA runner does **not** start Minecraft by itself; the operator-provided checks must exercise actual Minecraft, backend and databases. Only the protected `migration-ga-certification` runner may access the signed credentials and evidence.

**Supported Gravit source JARs for GA:** 5.7.0–5.7.12 after an independently approved JAR SHA-256. Inventory recognizing 5.7.13 does not authorize certifying it. Imported JAR modules are not binary-compatible by default. A source-port or functional replacement must be verified on the target project, otherwise it remains a manual/blocked item.

## Snapshot preparation — a real file read, not an expected digest

1. Fence *all* writers to each source and target environment, including Paper/Forge/NeoForge servers, proxy, external SQL data writers, upload jobs, and other independent processes. Stopping one systemd service alone does not fence the other processes.
2. Produce **separate** immutable or quiesced source and target snapshots. Each snapshot directory must contain `world/`, `plugins/` and a UTF-8 `player-uuids.txt` (one lowercase hyphenated Minecraft UUID per line). The world directory must contain real world files. An empty `plugins/` directory is permitted for a Vanilla project with no plugin data, but **both** snapshots must match. A source and target cannot point to the same directory. Store snapshots on local operator-controlled storage. The checker rejects symlinks and unsupported filesystem entries; it reads file bytes, not caller-supplied hash values.
3. Only the root `world/session.lock` transient file is intentionally ignored, and this exclusion is recorded for the source and target separately. No other files, including playerdata, level data, plugin SQL exports and economy/inventory records that the project stores in those trees, are silently excluded. For data stored **outside** those trees (e.g. PostgreSQL/MySQL economy or permission plugins), the operator must add an independent database reconciliation proof in the `uuid-world-plugin-data` probe and the change ticket.
4. Compare the fenced snapshots before certifying:

```bash
go -C tools/migration-ga run . audit-state \
  --source /srv/migrations/fileauth/source-snapshot \
  --target /srv/migrations/fileauth/target-snapshot \
  --output /srv/private/fileauth-state-audit.json
```

The command fails if a file, directory tree or UUID roster differs. The output is a private, immutable-on-creation JSON file containing exact tree digests, UUIDs, counts and exclusions. **Do not** run this on a live/writable world and treat the result as a consistent snapshot. The operator must ensure snapshot consistency before the read.

## Plans and certification

For each reference add to the 0.44.9 GA JSON plan:

```json
{
  "snapshotSourceDir": "/srv/migrations/fileauth/source-snapshot",
  "snapshotTargetDir": "/srv/migrations/fileauth/target-snapshot"
}
```

These keys are *additional keys* to the full operator plan described in [0.44.9 integration acceptance](gravit-integration-acceptance.md); this fragment is not a complete plan. They are required for 0.45.0. The native audit runs **again inside `certify`** for `uuid-world-plugin-data`: its calculated hashes and UUID list must match the operator probe's structured `never/gravit-state-audit/v1` evidence **and** the independently fetched MIG13 player identities. A probe that simply returns `passed: true` or a written SHA-256 without the actual files is refused. The GA verifier also rechecks retained state-audit evidence against the signed receipt.

Generate the per-project worklist from the *current* verified backend report before any cutover:

```bash
export LAUNCHER_MIGRATION_GA_TOKEN='<short-lived admin credential>'
go -C tools/migration-ga run . manual-actions \
  --plan /srv/private/ga/fileauth-single.plan.json \
  --output /srv/private/ga/fileauth-single-worklist.md
```

This produces concrete manual items for that migration report, plus the operator obligations for backup, external traffic, authentication resets, changes after cutover and rollback. All items must be separately checked and evidenced in the change ticket. The file itself does not certify that a human performed the actions. The file contains identifying source paths and must remain private.

After real probes for each class, `certify` and `verify` produce and validate the signed `launcher.gravit-ga-execution.v3` certificate. Old `v2` / 0.44.9 signatures are deliberately ineligible. Re-run after changing code, archive bytes, plan, source or game state.

**Before GA promotion**, invoke the live check (offline `verify-cohort` is useful for archival verification, but is not the production release gate):

```bash
go -C tools/migration-ga run . verify-cohort-live \
  --public-key /srv/private/ga/trusted-public.pem \
  --fileauth-single /srv/private/ga/fileauth-certificate.json \
  --fileauth-single-evidence /srv/private/ga/fileauth-evidence \
  --fileauth-single-plan /srv/private/ga/fileauth-single.plan.json \
  --sql-modded /srv/private/ga/sql-certificate.json \
  --sql-modded-evidence /srv/private/ga/sql-evidence \
  --sql-modded-plan /srv/private/ga/sql-modded.plan.json \
  --proxy-network /srv/private/ga/network-certificate.json \
  --proxy-network-evidence /srv/private/ga/network-evidence \
  --proxy-network-plan /srv/private/ga/proxy-network.plan.json
```

It requires `LAUNCHER_MIGRATION_GA_TOKEN` and rejects absent private evidence, invalid signatures, changed original Gravit archive/JAR, stale report, altered operator review, revoked/rolled-back target or inconsistent project. The signed certificate alone never authorizes traffic changes or proves an operator is trustworthy.

## откат ограничения

Record the source/target writer fence, deployment route revision, restore point, backup verification and post-rollback player world/UUID/inventory/economy checks. The `operational-rollback-drill` and `negative-rollback` checks must actually exercise the rollback and its refusal path on an isolated real copy. After players modify the Never world, an old Gravit backup is **not** a lossless restore. Reconcile the newer player and plugin data under fenced writers before switching traffic back. Never mark a failed, unsupported or untested case PASS.

## What the local code checks do not prove

Go unit/race tests validate hashing, signature verification, strict input handling, snapshot comparisons and live-backend validation using a test HTTP server. They do **not** constitute production PostgreSQL, Java Minecraft, RCON, ServerBridge, Windows/macOS or DNS/proxy cutover acceptance. The canonical workflow `.github/workflows/gravit-migration-ga-0340.yml` includes the full CI build matrix and three isolated live reference projects, but an authorized operator must run it and independently inspect raw evidence and the documented manual actions before declaring Migration GA certified.
