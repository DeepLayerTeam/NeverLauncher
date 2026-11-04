# Launcher 0.22.4 — File Ownership, repair and safe cleanup

## Executable behavior

Manifest v2 now signs both `files[].ownership` and `fileRules[]`. The same policy is validated by the Go API before persistence and publication, by Runtime before file inspection/download/repair/cleanup, and by the CLI manifest updater. Neither historical Manifest v1 signatures nor published v2 payloads are rewritten. The new PostgreSQL migration `0058_file_ownership_0224.sql` persists per-file ownership for new uploads; existing rows default to an empty ownership field to preserve the previous wire format.

Ownership values:

| Value | Installation / repair | Verification / cleanup |
|---|---|---|
| `required` | Download / replace from a signed URL; `required=true` | Must match SHA-256; missing is a repair failure |
| `managed` | Download / replace from a signed URL | Must match SHA-256; may be removed when absent from the next release if explicitly tracked |
| `optional` | Not automatically downloaded when absent unless an explicit `verify` rule requires it; a present corrupt copy is repaired | Missing allowed by default; user installation choices remain separate until P05/P09 |
| `user-owned` | Never overwritten or deleted by repair / cleanup | Not hash-verified against the release |
| `generated` | Never downloaded, never overwritten | Exempt from manifest verification |

Missing `ownership` on existing v2 files is interpreted as `required` if `required=true`, otherwise `optional`. This is a *runtime default*, not a rewriting of the signed JSON. `required=true` with `user-owned`, `generated` or `optional` is invalid.

The following paths are always protected even if an administrator accidentally marks them managed: `saves/`, `screenshots/`, `resourcepacks/`, `shaderpacks/`, `config/`, `logs/`, `crash-reports/`, `diagnostics/`, `.launcher/`, `.launcher-quarantine/`, `options.txt`, `optionsof.txt`, `servers.dat`, `usercache.json`. These are protected case-insensitively, including descendants. Conflicting rules and explicit managed-file references to protected paths block v2 release validation. Legacy v1 repair and cleanup also preserve these protected locations.

## Signed include / exclude / verify

Example fragment of a Manifest v2 **before** signing (other normal v2 Manifest fields omitted):

```json
{
  "files": [
    {"path":"mods/core.jar", "size":123, "sha256":"<64 hex characters>", "url":"https://download.example/mods/core.jar", "required":true, "executable":false, "ownership":"required"},
    {"path":"mods/optional.jar", "size":123, "sha256":"<64 hex characters>", "url":"https://download.example/mods/optional.jar", "required":false, "executable":false, "ownership":"optional"}
  ],
  "fileRules": [
    {"pattern":"mods/**", "action":"include", "ownership":"managed"},
    {"pattern":"saves/**", "action":"exclude", "ownership":"user-owned"}
  ]
}
```

`pattern` accepts exact slash-separated relative paths and anchored `<directory>/**` recursively. Absolute paths, traversal, mixed slash formats, partial wildcards and overlapping rules are rejected. `exclude` explicitly protects matching user-owned/generated content. `verify` makes matching optional files mandatory for verification/repair (and cannot select user-owned/generated data). `include` permits quarantine of *unlisted* files only within an explicitly managed scope. Without a signed `include`, unknown files are preserved. Default protected directories take precedence over every rule.

All managed download bytes are staged to exclusive `.nlpart-*` files, validated against length and SHA-256, flushed and synchronized before a final switch. The runtime refuses symlinks in target paths and parent components. On Windows an existing managed target is temporarily backed up and restored if installation fails; Unix uses an atomic rename over the old managed target. A clean/repair request can only execute against an Ed25519 Manifest verified against a **pinned public key**; cleanup now requires that key from Desktop's Tauri bridge.

## API, CLI and migration

- `POST /api/v1/packages/{packageId}/files` multipart accepts `ownership=required|managed|optional`; default `required`. User-owned or generated content must not be uploaded as a managed release blob. Ownership is persisted in the SQL `files` row and copied to the signed Manifest during package validation.
- The existing authenticated Manifest editing request supports `fileRules` alongside its existing minecraft/runtime/directories fields. Rules are covered by Ed25519 signatures, and published versions remain immutable. An incomplete draft may be edited; publishing requires a valid managed file URL and SHA-256.
- CLI manifest updates apply only listed managed/required/selected optional files, do not treat user-owned/generated files as targets, and remove only old tracked managed/required paths that no longer appear. CLI client cleanup/rollback no longer sweep arbitrary unknown `mods/` files: only paths from the installed `.launcher/client-state.json` are eligible for cleanup/rollback operations.
- The migration is additive and must be applied normally by API and CLI migrators before version 0.22.4 uses SQL file rows; migration `0057` must already exist. No old release signing payloads, snapshots or profile revisions are migrated or re-signed.

## Validation commands

```sh
cd services/api && GOPROXY=off go test ./internal/model ./internal/dbmigrate
cd cli && GOPROXY=off go test ./cmd/launcher -run 'Client|Rollback|Transactional|Updater' -count=1
cd cli && GOPROXY=off go test ./internal/dbmigrate
cd runtime/runtime && cargo test --lib
python3 scripts/version/manage.py check
```

The model and CLI integration tests assert protected-path rejection, duplicates, rules overlap, v1 signing compatibility, SHA-256 coverage, preservation of saves/screenshots/resourcepacks/options/config/optional/untracked mods, managed-file replacement, real repair, and rollback. The Rust unit tests cover signed policy tampering, signed cleanup, symlink rejection and legacy repair without settings replacement. Rust tests require a locally installed Rust toolchain. PostgreSQL live migrations and Desktop multi-OS E2E must still be run in CI/production-like environments before certifying an official production release.

### Scope boundary

This version deliberately does **not** claim transactional release-version sync/channel-head CAS (P08), end-user optional mod selection (P09), or profile workspaces (P06). The new manifest ownership policy is enforced by the actual repair/download/cleanup/update paths, not merely defined as a schema.
