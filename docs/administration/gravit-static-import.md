# Launcher 0.22.10 — Static Gravit ClientProfile import

The importer is accessible under **Admin → Profiles → Gravit static import**. It processes a single Gravit `ClientProfile` JSON document. Inputs must be valid JSON (remove JSONC comments with a JSON-aware editor), at most 1 MiB. Input is never evaluated; no Java code, loader agent, shell, optional action or module from Gravit is executed.

## Endpoints

Both routes require `project:write` in the destination project; mutation additionally requires `release:prepare`.

* `POST /api/v1/admin/projects/{projectId}/profiles/inspect-gravit` (read-only).
* `POST /api/v1/admin/projects/{projectId}/profiles/import-gravit` (exclusive profile creation plus private Build Workspace).

Example inspection request:

```json
{
  "id": "gravit-vanilla",
  "name": "Gravit Vanilla",
  "loaderHint": "vanilla",
  "source": {
    "title": "Vanilla 1.20.4",
    "version": "1.20.4",
    "mainClass": "net.minecraft.client.main.Main",
    "recommendJavaVersion": 17,
    "classLoaderConfig": "SYSTEM_ARGS",
    "classPath": ["minecraft.jar"],
    "updateVerify": ["minecraft.jar"]
  }
}
```

The response includes `data.format=launcher.gravit-import-report.v1`, exact source SHA-256, `ready`, a deterministic field-by-field `fields` list, `summary`, normalized Never `profile`, `settings` compatible with a Build Workspace, and server descriptions for manual registration. On `inspect-gravit`, **nothing is persisted**. Unknown fields and unsafe conversions are `blocked`; fields needing operator decisions are `manual`. Both prevent import.

For commit send the *same* input and also:

```json
{
  "sourceSha256": "<sourceSha256 from inspect>",
  "channel": "stable",
  "version": "1.0.0"
}
```

The body must also include `id`, `name`, `loaderHint`, and `source` from inspection. The server reconverts the input (does not trust a client-supplied report), checks `sourceSha256`, atomically creates a **new** unprivileged Profile v2 and a private workspace pinned to revision 1. PostgreSQL uses one ACID transaction for profile, immutable snapshot and workspace; MemoryRepository uses coordinated locks. Duplicate identities reject the entire operation. Retries must still inspect existing state if a network response was lost.

The workspace starts in `importing`. Operators must import the actual game directory, scan, stage required JARs, validate the signed classpath and file rules, and build through the existing release pipeline. Import never publishes or signs arbitrary Gravit data. Existing signed Never manifests, snapshots and access permissions are not modified.

## Semantic mapping & fail-closed rules

| Gravit | Never / status |
| --- | --- |
| `title`, `info`, `version`, `mainClass` | Profile metadata, Minecraft version, Runtime mainClass — mapped |
| `minJavaVersion`, `recommendJavaVersion`, `maxJavaVersion` | Typed Java major constraints; Gravit `999` becomes unbounded maximum `0` — transformed |
| `settings.ram` | Recommended RAM; `0` means automatic — transformed |
| `jvmArgs`, `clientArgs` | Ordered argument arrays validated by production runtime constraints |
| `classPath` | Ordered signed `.jar` entries; directory roots are **blocked** until enumerated; JAR hashes supplied during staging |
| `classLoaderConfig=SYSTEM_ARGS` | Native JVM invocation — transformed; `LAUNCHER`, `AGENT`, `BRIDGE` and unknown values blocked |
| `altClassPath` | Only an empty list is supported; nonempty alternate bootstrap classpath blocked |
| `compatClasses`, `updateOptional` | Nonempty bootstrap/additional actions blocked, including JVM arguments, file moves, dependencies, conflicts, triggers |
| `update`, `updateVerify` | Conservative `verify` rules (no authorization to delete unknown files). Exact and folder patterns normalized, merged deterministically |
| `updateExclusions` | `user-owned` exclude rules; overlapping incompatible rules blocked |
| `servers`, `settings.autoEnter`, `settings.fullScreen`, `assetIndex`, nonzero `sortIndex`, custom `properties` | Manual operator decisions; never silently discarded |
| `limited=true` | Blocked until access policy is explicitly reimplemented in Never; source owner credentials/ACLs never imported |
| Unknown keys, unsafe paths, Java agents, conflicting rules | Blocked and identified in the report |

**Safety:** verify and exclude rules cannot authorize cleaning unknown managed files; user saves, screenshots, resourcepacks, settings, and other protected paths must not be overwritten. Classpath paths are not trusted until concrete signed files are staged. No generated report is itself a runnable or publishable Manifest. The Admin report is downloadable as JSON for audit/migration planning.

## Local tests

```sh
cd services/api
GOPROXY=off go test ./internal/model -run TestGravitImport -count=1
```

The full API build/HTTP and PostgreSQL integration tests still require the dependencies, services and toolchain defined by the repository CI; successful model tests alone do not certify the entire release.
