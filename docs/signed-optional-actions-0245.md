# NeverLauncher 0.24.5 — Signed Optional Actions

## Execution contract

`manifest.schemaVersion: "3.0"`, `componentCatalog.schemaVersion: "5.0"`.
The release owner publishes a signed, immutable catalog with a domain-separated
`neverlauncher.component-catalog.v5\0` SHA-256 digest. The catalog digest
includes ordered actions and their arguments, in addition to the complete v4
topology, dependency rules and conditions. Native verification uses the pinned
release key; the local preset never changes the signed manifest.

Each component has an optional `actions` array (maximum 64). Action types are:

- `File`: `{ "type":"File", "path":"mods/performance.jar" }`. Where at least one
  `File` action is specified, install only the component's signed `File` and
  `ClassPath` paths. Without any `File` action, install all files in that component's
  signed `files` array (compatibility with pre-v5 catalogs).
- `ClassPath`: `{ "type":"ClassPath", "path":"libraries/optional.jar" }`.
  Add this component-owned, selected, signed `.jar` to the real launch classpath,
  after the base compatibility/manifest classpath. Native runtime verifies its
  exact signed size and SHA-256 before launching; duplicate paths and modular
  JVM entrypoint combinations fail closed.
- `JvmArgs`: `{ "type":"JvmArgs", "args":["-Dfabric.log.level=debug"] }`.
  The runtime appends only approved single-token options. Supported: `-ea`, `-da`,
  `-XX:+UseG1GC`, bounded `-XX:MaxGCPauseMillis=N`, and single-token properties
  under `neverlauncher.optional.`, `fabric.`, `forge.`, `neoforge.`, `mixin.`.
  Property values are simple printable identifiers, not paths, argument files or
  Java execution instructions. Entrypoint, memory limits, agents, bootclasspath,
  java.library.path and inherited JVM injection variables are never configurable
  by optional actions.
- `ClientArgs`: `{ "type":"ClientArgs", "args":["--never-optional-debug=1"] }`.
  Accepted namespaces: `--never-optional-`, `--fabric-`, `--forge-`,
  `--neoforge-`, `--mixin-`. Client identity, session tokens, game directories,
  server targeting and Minecraft version arguments are not accepted.

Arguments are single OS-process tokens, not shell fragments. Each action can
contain at most 32 arguments. Unknown action types and unsafe or duplicate
arguments/paths block publication and client installation.

## Actual execution

1. Backend draft mutation accepts catalog v5 and recalculates its digest.
   PostgreSQL migration 0065 permits v5 while retaining the published-release
   immutability rule.
2. Native resolver chooses the installed preset under signed dependency and
   conditions rules; `File`/`ClassPath` determine which owned files are staged,
   SHA-256-checked, committed and kept during rollback.
3. The native builder requires a matching active signed release and applies
   action classpath entries/flags to the real `LaunchPlan`; its deterministic
   digest changes with the actions.
4. Before spawning Java, selected executable classpath files are checked against
   the manifest's pinned SHA-256 and size, with symlink avoidance. The runtime
   applies the same JVM memory and entrypoint protection policy as for normal
   signed runtime arguments.
5. Two different presets containing the same files but different signed actions
   still require a new install/selection; a dropdown change is insufficient.

## Security and scope

Optional actions are approved by the same release owner who already controls
Java runtime and the files of a release. Untrusted players cannot author action
payloads, escape managed file ownership or add JVM agents. Existing v1–v4
catalogs remain supported and MUST NOT carry v5-only actions.

The v5 action grammar is deliberately narrower than arbitrary Gravit JVM/client
arguments. Arguments not on this allowlist are rejected instead of partially
interpreted; this is a security restriction, not full arbitrary OptionalAction
migration. Server-verified entitlement evidence for condition permissions
remains outside this release (existing 0.24.4 fail-closed behavior).

## Verification commands

```sh
cd services/api && go test ./internal/model ./internal/dbmigrate
cd cli && go test ./internal/dbmigrate
python scripts/version/manage.py check
cd runtime/neverruntime && cargo test component_actions_0245
```

The Rust tests include a Go/Ed25519-signed manifest v5, positive launch-plan
action application, unsafe argument rejection and modified signature rejection.
A successful E2E build across supported operating systems is required before
claiming production deployment readiness.
