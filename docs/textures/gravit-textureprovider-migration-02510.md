# Launcher 0.25.10 — Gravit TextureProvider Migration

This version imports **real** GravitLauncher/TextureProvider texture records into the existing Launcher local-project texture pipeline. It reads either the official upstream PostgreSQL table (`textures`) or an offline JSON export. No Gravit credentials, sessions or upstream access tokens are imported. The command is operator-only; there is no public migration endpoint.

## Source format and identity mapping

Supported upstream PostgreSQL fields are `id UUID`, `user_uuid UUID`, `texture_type` (`SKIN` / `CAPE`), `file_hash` (SHA-1 or SHA-256 of the **original PNG**), `file_url`, and optional `metadata.model` (`slim` or `default`). The schema matches the upstream TextureProvider table in `migrations/001_initial.sql` at `GravitLauncher/TextureProvider`. Supported JSON exports are arrays of objects with those snake_case properties. JSON may additionally provide `object_key` (relative to the trusted source root/bucket).

Launcher makes **no** username-based, user-ID-derived, or official-UUID identity guesses. It imports a row only if `user_uuid` equals an existing `minecraft_profiles.uuid` with `issuer=launcher, realm=local`, or an administrator explicitly maps a verified legacy UUID to an existing local UUID. Mapping is a JSON array:

```json
[
  {"source_uuid":"11111111-1111-1111-1111-111111111111","target_uuid":"22222222-2222-2222-2222-222222222222"}
]
```

This is an **operator assertion**, not proof from the legacy source: review account ownership manually before import. No import is permitted into an official Minecraft profile. Unmatched records appear in the report.

## Prepare and execute

Apply the normal Launcher migrations **through 0073_texture_gravit_import_02510** before running this command. Back up the target database and local/S3 bucket first; verify quotas and cape entitlements. Set the same target environment variables used by the API (`NEVERLAUNCHER_DATABASE_DSN`, `NEVERLAUNCHER_STORAGE_DRIVER`, `NEVERLAUNCHER_STORAGE_LOCAL_PATH` or `NEVERLAUNCHER_STORAGE_S3_*`).

Example: source PostgreSQL + local source files. Do not put DSNs with credentials in shell history or log output: prefer preconfigured environment-file secrets.

```bash
cd services/api
# The source key template MUST reflect the actual legacy storage layout.
# Gravit may use hash.png, skins/<hash>.png, or other layouts.
export NEVERLAUNCHER_DATABASE_DSN='postgres://.../launcher'
export GRAVIT_SOURCE_DSN='postgres://.../texture_provider'
go run ./cmd/gravit-textures-import-02510 \
  --source-id gravit-prod-01 --source-dsn "$GRAVIT_SOURCE_DSN" \
  --source-root /srv/gravit/storage --source-template '%kind%/%hash%.png' \
  --mapping ./minecraft-identity-mapping.json \
  --dry-run --report ./gravit-dry-run.json
```

The dry run validates *real file bytes*, verifies source digest, decodes/normalizes PNG and checks target identities. It neither writes the destination blob nor updates target assignments. When satisfied, rerun without `--dry-run` using another report path. Existing Launcher selections are **never overwritten by default**; add `--replace` only after explicit approval (with CAS checking; concurrent updates are rejected). Record and review all `quarantined`, `unmatched`, `skipped-existing` and `blocked` items.

For offline JSON, use `--source-json /path/to/export.json` instead of `--source-dsn`. Export the actual `textures` rows as JSON from the source database; do not export secrets. For S3 source, set `GRAVIT_S3_ENDPOINT`, `GRAVIT_S3_BUCKET`, `GRAVIT_S3_REGION`, `GRAVIT_S3_ACCESS_KEY`, `GRAVIT_S3_SECRET_KEY`, optionally `GRAVIT_S3_PATH_STYLE`, and pass `--source-s3` rather than `--source-root`. This reads S3 **directly with authenticated SigV4**, from the configured bucket; `file_url` from legacy records is never fetched. All relative object keys are validated, and keys do not control S3 host or credentials.

`--source-template` supports `%kind%` (`skin` or `cape`), `%KIND%` (`SKIN`/`CAPE`) and `%hash%` (original source digest). For example `--source-template 'skins/%hash%.png'` can only import skins. If skins and capes live in separate directories, either supply per-row `object_key` in a vetted JSON export, use a common template `'%kind%/%hash%.png'`, or run separate imports with a **distinct source ID** for each appropriately filtered export. Keys cannot contain `..`, absolute paths, empty components or backslashes. If a source points only to an HTTP URL and no trusted local/S3 object is available, it is quarantined: import the PNG to the trusted source storage first, rather than bypassing the SSRF-safe fetcher.

## Import behaviour and recovery

Each row is checked independently. SHA-1/SHA-256 verification is against source bytes **before** PNG normalization; resulting content-addressed SHA-256 is stored through the existing normalizer, prewrite staging, local/S3 immutable writer, owner quotas, cape policies and revision-controlled assignment. `source=imported` and `event=gravit-import` are recorded in the existing tables. A `texture_gravit_import_receipts` row (source ID + legacy ID) is committed **atomically** with its selection to prevent a second import from overwriting a subsequently changed skin. Re-running the same source ID reports `already-imported`; choosing a new ID is a new migration and should not be used to bypass provenance.

Rows with missing objects, invalid/oversized PNG, unknown digest format, wrong source digest, unsupported model or type, unmatched target UUID, disabled cape permissions or exceeded quotas are not selected. The report is atomically written with mode 0600, recording per-row reasons; any `blocked`, `unmatched`, or `quarantined` outcomes result in nonzero exit status while valid rows remain committed. Inspect report before repeating. An interrupted import can be repeated with the same source ID. Orphaned staging data and immutable objects are handled by the existing 0.25.3 garbage collector after its safety window.

## Verification checklist

1. Start with a fresh backup; test dry run using valid, truncated, malformed, oversized, symlink-escaping, source-hash-mismatch and missing-object samples.
2. Perform a small canary batch; inspect `texture_gravit_import_receipts`, `texture_assignment_revisions` and `texture_saved_items` and confirm original hashes are not treated as normalized hashes.
3. Run twice: second execution must be `already-imported` without changing any revision. Re-test after a player changes their selection.
4. Verify cape policies and quota denials, official account isolation, preview and signed Yggdrasil `textures` in a real client.
5. Check local and S3 storage, backup/restore and GC. Keep original Gravit storage read-only until rollback/verification is complete.

**Certification limits:** PostgreSQL integration, a real source database, production S3/MinIO, and Minecraft end-to-end testing must be run in a provisioned environment. Unit tests are not substitutes for those checks.
