# NeverLauncher 0.33.2 — MIG02 Gravit Compatibility Detector

This release implements a **working, read-only source detector** behind the PostgreSQL-backed durable migration run introduced in 0.33.1. It does not implement Gravit import or a trusted transition. A report with no blocking findings is still `manual`, `cutoverAllowed=false`.

## Operation

1. Create a migration run (`nl migrate gravit create ... --project PROJECT --key STABLE_KEY`) and execute its Never baseline (`nl migrate gravit execute ... --run RUN_ID`). Wait for `status=prepared`, `step=source_assessment`.
2. Prepare a **configuration archive** of the Gravit installation. Include `LaunchServer.json`, `LaunchServerRuntime.json`, `profiles/*.json`, optional module JARs / settings, `ServerWrapper.json`, and optionally `LaunchServer.jar` for manifest-based version recognition. The archive is capped at 64 MiB compressed / 128 MiB declared expanded. This is a configuration assessment, **not a content/assets transfer**: do not include worlds, giant clients or backups. Prefer ZIP creation under a controlled temporary directory. File names must have safe, unique, case-insensitive-normalized paths.
3. Run:

```bash
nl migrate gravit assess --backend https://never.example --token "$NEVERLAUNCHER_TOKEN" \
  --run RUN_ID --source ./gravit-config.zip --version 5.7.12 --output ./compatibility-report.json
nl migrate gravit compatibility --backend https://never.example \
  --token "$NEVERLAUNCHER_TOKEN" --run RUN_ID
```

Alternatively use **Admin → Migration Center** to select the run and upload the ZIP. The binary endpoint is `POST /api/v1/admin/migration-runs/{runId}/compatibility` (`Content-Type: application/zip`, optional `X-Gravit-Version`); `GET` retrieves the last saved report. Requires `settings:manage` and PostgreSQL. Never send admin credentials over remote HTTP (CLI allows only HTTPS or explicit IP loopback).

## Detection behavior

- Inspects Gravit LaunchServer auth cores, textures and security handlers, client profiles, optional action types, runtime JSON/settings, module JAR inventory/configuration, ServerWrapper JSON and legacy environment settings. No Java code is loaded or executed.
- Rejects invalid archives, traversal/symlinks, duplicate members, excessive decompression and malformed/ambiguous JSON (including repeated JSON keys). The report contains classifications, component paths, findings, source SHA-256, and claimed/detected versions **without configuration body contents, passwords, token values or keys**. Uploaded ZIP bytes are discarded after assessment; use TLS and observe the infrastructure's request-body logging policy.
- Recognizes `5.7.0`–`5.7.12` as a *candidate version family* only after finding a matching Gravit/LaunchServer `Implementation-Version` in the packaged `LaunchServer.jar` manifest. The JAR manifest is **untrusted metadata**, not a verified upstream signature. Operator `--version` alone remains `unverified`; mismatch with the manifest is `blocked`. No 5.7.x version is certified for fully automatic migration by this detector.
- Unknown auth cores, conflicting defaults, invalid profile fields, unsupported optional actions and ambiguous LaunchServer instances are blocking findings. Known auth providers and optional actions require transfer/mapping checks in later milestones. Third-party JARs are never imported or executed; operator reviews their semantics in MIG08.
- `status=prepared` remains the 0.33.1 Never baseline state; presence of a compatibility report does not mark the migration complete. The migration coordinator, CLI and UI cannot perform import/cutover/rollback in 0.33.2.

## Replay / audit

`migration_compatibility_0332` stores only sanitized JSON. Each new source hash updates the report and increments the run revision in the **same transaction** as an append-only `gravit_compatibility_assessed` event. Retrying an identical ZIP and version claim returns the original report without adding another event. Reusing the same hash with a conflicting version claim returns HTTP 409, requiring operator reconciliation. No source archive persists in SQL.

## Tests / limitations

Unit/race tests generate representative 5.7.x-shaped ZIP fixtures (based on published configuration structures), exercise spoof/conflict handling, unknown auth/optional actions, ServerWrapper credentials, duplicate JSON keys, ambiguous installations and unsafe archive entries. This is **not a substitute for pinned, independently verified upstream 5.7.x release fixtures**; such validation and a real migration rehearsal must precede GA. CI runs Go 1.27.3 native tests against disposable PostgreSQL and builds Admin; local environments without that toolchain cannot claim full CI success.
