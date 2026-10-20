# NeverLauncher 0.24.6 — Resolved Download & Ownership

This release modifies the **actual NeverRuntime transactional install path**, not the API declaration of a future resolver. It uses the existing signed catalog v1–v5; no extra manifest version or database schema migration is needed.

## Execution path

1. `durable_downloads::start_with_preset` verifies the owner's signed manifest against the **Desktop-pinned key** and computes `resolved_download_0246::resolve` for the requested signed preset.
2. The durable download job stores `resolvedPlanSha256`. `pending`, `resume` and `perform` recalculate and compare it; mismatched selected plans are rejected before installation. Pre-0.24.6 jobs without the new field can still be read and checked against the signed manifest.
3. The resolved plan contains only paths selected by `component_catalog_0241::active_files`, applicable to this OS and eligible for managed download under `file_ownership` rules. It records ordered `(path, SHA-256, size)` entries, signed-manifest identity and requested preset. This is the same effective selection used by dependency, condition and signed-action resolution. All non-selected optional component paths are excluded.
4. `transactional_release::install` checks the existing active signed release and its registered ownership set. Unchanged files are reused only when previously registered as managed and their **current bytes** match the size and SHA-256 signed in **both** manifests. Unregistered player files can never become managed simply because their bytes match a published artifact.
5. Only the missing/changed resolved paths reach `download_scheduler::run_selected`; the scheduler uses the existing content-addressed SHA-256 cache, secure mirror/fetch pipeline, resume support, and verifies all staged bytes. Reused files skip copying, HTTP and cache lookups; final `DownloadResult` includes their byte reuse and skipped-file count.
6. `commit` re-evaluates whether each byte-identical file can be reused, and requires verified staged bytes for all other paths **before writing the switch journal**. It skips the live-file replacement for reusable paths, while its write-ahead journal, previous-ownership record, verified backups and rollback machinery continue to account for the **entire selected set**, not just downloaded deltas.
7. Only entries registered by the **previous active** release are eligible for retirement. Untracked files are never enumerated for deletion. Preset changes or version upgrades refuse to retire modified managed files; repair of the **same signed selection** may overwrite a damaged registered file after a verified replacement is prepared.
8. The installed release record stores the resolved plan digest and validates it on subsequent recovery, launch, rollback and preset checks. Prior release records without this additive digest remain compatible; newly committed releases always include it.

## Important trust boundaries

- The plan digest is a **locally derived identity**, **not** a new self-signed authorization artifact. Authority remains with the Ed25519-signed manifest and pinned trusted public key. The digest is recomputed, not blindly trusted from local journals.
- No input adds files, arguments, executables or actions beyond the signed manifest. All filenames still pass the existing collision, protected user-path, and symlink/reparse checks.
- Cache objects are addressed and verified by the manifest SHA-256 and copied to staging; never hardlinked into game installations.
- A valid but different preset cannot be launched without an installed matching plan. A file removed from a preset is not treated as managed merely because it happens to be in `mods/`.
- Local modification of a previously managed file prevents destructive preset migration (except explicit repair of the same selection). A duplicate but previously **unmanaged** file blocks initial ownership takeover even if its hash equals the signed artifact.
- Rollback restores the previous registered set and removes only newly registered files. Signer trust and anti-rollback generations are unchanged.

## Tests and certification

Run from the repository root:

```bash
python3 scripts/version/manage.py check
cd runtime/neverruntime
cargo test resolved_download_0246
cargo test v5_resolved_plan_reuses_unchanged_bytes_and_rolls_back_only_owned_paths_0246
cargo test installer_uses_only_resolved_delta_and_checks_real_selected_files_0246
cargo test deselect_must_not_delete_locally_modified_previous_component_0246
cargo test identical_untracked_file_must_not_be_claimed_as_managed_0246
cargo test
```

Additional release-gate verification is required on Windows, Linux and macOS for symlink/reparse points, locked files, disk-full interrupted switch, content-cache corruption, pause/resume, rollback and real Minecraft launch. Rust toolchain was not installed in the authoring environment; these tests are **added but not represented as having passed**.

Go model and migration regression tests:

```bash
(cd services/api && go test ./internal/model ./internal/dbmigrate)
(cd cli && go test ./internal/dbmigrate)
```

Known existing limitation carried forward from 0.24.4: permission-gated components remain fail-closed without a real server-issued entitlement proof. 0.24.6 does not claim to complete entitlement issuance or ServerBridge verified-plan attestation.
