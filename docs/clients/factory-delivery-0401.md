# Client Factory → Build Workspace → Desktop / Runtime (0.40.1)

The API executes the existing Client Factory CLI to materialize a real Minecraft
client. The `POST .../deliver` operation makes those verified files first-class
Build Workspace objects; no locally exported ZIP must be re-uploaded by an
operator. It deliberately **does not** publish a release or invent runtime
verification results.

## Operator sequence

1. Configure an absolute, trusted executable path in `NEVERLAUNCHER_FACTORY_CLI` and
   a private absolute directory in `NEVERLAUNCHER_FACTORY_ROOT`. For Forge-like
   installation, configure `NEVERLAUNCHER_FACTORY_JAVA` where necessary.
2. In Admin create a client profile with an **exact** Minecraft version and an
   exact loader version (for modded clients); create a new, empty Build Workspace
   with matching Java major and default launch settings.
3. Choose a target OS/architecture, build from Minecraft or a supported modpack,
   and inspect the completed job's verified InstallPlan and execution logs.
4. Choose **Перенести сборку в Build Workspace**. This calls
   `POST /api/v1/build-workspaces/{workspaceId}/factory/jobs/{jobId}/deliver`
   with `{ "revision": <current workspace revision> }`, authorized with
   `file:write`. Only a completed job owned by the same workspace/operator/project
   is accepted.
5. The backend invokes `runtime client-factory verify` again; checks the
   returned reproducibility hash; verifies all source file bytes and rejects
   symlinks/path traversal; encrypts every output to private Workspace storage;
   reads back each object; then commits all files and the exact version metadata
   path in one revision-checked database operation.
6. In Admin run Stage → Validate → Build. The backend creates its immutable
   version package using the existing signed delivery pipeline. Continue with
   package validation, signing, staged runtime/game tests, and publication.
7. On Desktop fetch the **published, signed** manifest and complete standard
   Runtime download/repair, Java selection, compatibility launch-plan
   creation, launch and server join. The factory transfer alone cannot confirm
   successful Minecraft execution.

## Failure and retry behavior

- Bad or changed factory output, incorrect Minecraft/loader/Java, invalid
  metadata, occupied Workspace, stale revision or wrong authorization **fails
  closed**. The existing workspace record is not partly modified.
- File blobs stored before a failed commit are private and not referenced by a
  Workspace file list; deferred storage cleanup can remove unused objects.
- Direct transfer requires an empty unbuilt Workspace, preventing accidental
  replacement of the operator's already-staged content.
- Factory output is tagged for the requested target OS. Platform architecture
  is still subject to independent runtime certification; a built client is not
  proof of x64/ARM64 compatibility.
- Package signing/publication must still obey the project's independent
  trust, runtime acceptance and release verification gates.

## Local verification status

The existing Client Factory materializer fixture tests are executable with
Go 1.23.2. The API module declares Go 1.27.3 and requires external dependencies;
its tests could not execute in the offline container. No production Minecraft
binary, game account, live server join or cross-platform Desktop runner was
available here. Do not mark the end-to-end acceptance as passed without real
runtime/server logs and exact release-artifact evidence.
