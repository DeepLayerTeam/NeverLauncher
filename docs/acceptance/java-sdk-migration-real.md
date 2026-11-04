# NeverLauncher 0.52.8 — Java, SDK & Migration Acceptance

## Working code and local verification

Run on Linux with JDK 21, Go 1.23+, Node 22 and `tsc` 5.8.3:

```sh
umask 077
python3 scripts/acceptance/java_sdk_migration_0528.py local \
  --report /absolute/private-dir/0528-local.json
```

The executable local suite builds the real Gravit five-ported-extensions JAR and trusted JVM agent, executes a separate JVM Host and game-class transformation, checks denial for a mismatched agent digest, then tests Go, Java and TypeScript HTTP SDKs against actual local HTTP servers. It also executes the existing three-Gravit-project migration/verifier negative regressions and new 0.52.8 negative checks. The existing Java Host local test uses a simulated Go Broker and synthetic `net.minecraft` class: **local success does not certify installed production behavior**.

New Java REST SDK `requestStream` / `callStream` stream large binary data directly to an operator-supplied `OutputStream` (1 GiB hard limit; per-call limits, no redirect, bounded error body). Callers must discard partial destinations on error. Go's `CallStream` and TypeScript's `responseType: 'stream'` remain tested without response-sized allocations.

The real Gravit rehearsal tightens SHA-256 input reads against linked or replaced source ZIP, mapping, dry-run plan, mutable staged receipts and executable probes. This is executable source protection in the three-project migration path, not another manifest or compatibility label.

## Installed Java Host and genuine Minecraft evidence

Use a dedicated isolated project with a real 0.52.8 HTTPS Backend, deployed Java extension Host and Go Broker, short-lived project admin token, a test player and previously loaded migration identities/libraries. Provision a private mode-0600 config (`neverlauncher.java-host-live-0528/v1`) with keys:

- `format`, `isolatedProject: true`, `sourceCommit` (40 lowercase hex), `backendUrl`, `hostUrl`, `projectId`, `profileId`, `loaderVersion`, `testIdentifier`, `testUuid`.
- `libraryFile`, `librarySha256`, `libraryPath` (a real stored and broker-readable `libraries/`, `mods/` or `optional/` file, within the current Java Host SPI 512 KiB asset limit), `extensionJar`, `extensionJarSha256`.
- `agentArtifact`, `agentSha256`, `gameCompatibilityResult` (absolute existing `compatibility-result.json` from real native 0.52.4 Minecraft launch), `gameTargetId`, `ciRunId`, `ciRunAttempt`.

Provide secrets **only in environment variables** `NL0528_JAVA_HOST_TOKEN`, `NL0528_OWNER_TOKEN`, `NL0528_TEST_PASSWORD`. The executable sends live password/UUID checks, resolves and prepares a real content library, attempts a forbidden cross-project read, executes the JVM `profile.before-save` callback with allow/veto and then sends a real Admin profile PATCH to the Go Backend; it verifies a successful write and that a denied write did not change state. It applies the actual installed extension `state.migrate` callback to the isolated project. This is destructive staging acceptance, **never use against an owner's production world**.

The game step replays the original compatibility result and underlying server join/RCON/JVM logs using `inventory_0521.verify_compatibility` and rechecks their SHA-256. An ordinary launcher join is not agent proof: the exact `trustedAgentSha256` must be present inside the previously verified (hashed) `*-certification.json`, and it must match the installed trusted-agent artifact. If the native client pipeline cannot independently supply this observed binding, this step stays **BLOCKED**; placing an arbitrary `agentHash` in a new report never grants PASS. A signed Guard policy and Java-agent allowlisting still require separate 0.52.9 acceptance.

## Three distinct live Gravit projects

Use the existing `tools/gravit-port/ga_acceptance_0500.py`, unchanged in its obligation to requery the running PostgreSQL-backed Backend and validate 36 individually signed real checks for distinct `fileauth-single`, `sql-modded`, and `proxy-network` projects. It also executes 19 hash-pinned module behavioral probes and rechecks live trust after those probes; every receipt, source ZIP, signed update and Minecraft witness must match its exact run and project. Configure its original private `never/gravit-acceptance-0500/v1` config and an **empty 0700** independent evidence directory. The new 0.52.8 runner invokes this tool directly; its evidence must still be independently reviewed, and `productionGA` remains false.

## Historical NeverLauncher migrations

Run `legacy_upgrade_real_0528.py capture` against each **genuinely running original** 0.36.0 and 0.46.0 deployment before writer freeze. The private 0600 JSON config has:

```json
{
  "format": "neverlauncher.legacy-live-upgrade-0528/v1",
  "sourceVersion": "0.36.0",
  "baseUrl": "https://original-isolated-host.example",
  "ownerCredentials": "/absolute/private/owner.json",
  "projectId": "real-project", "profileId": "real-profile", "channelId": "stable",
  "sourceFiles": {"core_db": "/absolute/original/source.sqlite"},
  "storageRoot": "/absolute/original/objects",
  "targetStorageRoot": "/absolute/new/objects"
}
```

The capture uses a **real HTTP owner login**, reads the original project/profile/channel and canonical owner UUID and hashes disk sources and game storage. It stores neither passwords nor bearer tokens. Freeze competing writers and use the actual supported migration/cutover procedure; the script **does not pretend to be a data migrator**. After the migrated 0.52.8 Backend starts, invoke `verify` with the original immutable capture; it logs in again and compares the owner/project/profile/channel, disk sources, original immutable data and new target storage hashes. Any mismatch, missing older API, unsupported historical source format or competing writer is **BLOCKED**. The historical 0.36.0 route is not implicitly declared supported just because this script can request it; it must work on a real historical installation.

For both routes:

```sh
python3 scripts/acceptance/legacy_upgrade_real_0528.py capture \
  --config /absolute/private/legacy-original.json --output /absolute/private/original-capture.json
# Operator freeze + live cutover + update baseUrl in PRIVATE config to the migrated endpoint
python3 scripts/acceptance/legacy_upgrade_real_0528.py verify \
  --config /absolute/private/legacy-migrated.json \
  --source-capture /absolute/private/original-capture.json \
  --output /absolute/private/live-verify.json
```

## Combined external acceptance

The protected workflow `.github/workflows/java-sdk-migration-real-0528.yml` has a normal local CI regression job and a manual, isolated live job. The latter uses a **private 0600** config `neverlauncher.java-sdk-migration-0528/v1`:

```json
{
  "format": "neverlauncher.java-sdk-migration-0528/v1",
  "sourceCommit": "0123456789abcdef0123456789abcdef01234567",
  "java": {"config": "/absolute/private/java.json", "output": "/absolute/private/java-result.json"},
  "gravit": {"config": "/absolute/private/gravit.json", "evidenceDir": "/absolute/private/empty-0700"},
  "legacy": [
    {"sourceVersion":"0.36.0", "config":"/absolute/private/legacy-036.json", "capture":"/absolute/private/legacy-036-capture.json", "output":"/absolute/private/legacy-036-verify.json"},
    {"sourceVersion":"0.46.0", "config":"/absolute/private/legacy-046.json", "capture":"/absolute/private/legacy-046-capture.json", "output":"/absolute/private/legacy-046-verify.json"}
  ]
}
```

Run `python3 scripts/acceptance/java_sdk_migration_0528.py live --config /absolute/private/composite.json --report /absolute/private/final-0528.json`. It fails if **any** Java, Gravit or legacy branch lacks real evidence, if a tool executable or original file changes, if projects share a source, or if Git commits differ. A private result is written only after successful execution; status is `LIVE_CHECKS_PASSED_REVIEW_REQUIRED`, not `GA`. Independent review of final signed packages, Windows/macOS platform execution, PostgreSQL rollbacks, account and Minecraft support remains required for 0.53.0.
