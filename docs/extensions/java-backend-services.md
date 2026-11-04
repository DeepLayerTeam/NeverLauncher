# NeverLauncher 0.48.4 — Java-сервисы Backend

Java extensions call the existing authenticated Go Extension Host Broker through `ExtensionContext.runtime().backend()`; neither the Java SDK nor extensions connect to the database or obtain administrative tokens. No new public REST endpoints or untrusted classpath changes are necessary.

This release adds **real read-only** services backed by `repository.Repository` and `repository.DurableControlPlane`:

| SDK call | Host capability | Grant |
| --- | --- | --- |
| `projects(offset, limit)` | `project.list` | global `project:read` and global extension scope |
| `project(projectId)` | `project.get` | `project:read` for project |
| `profiles(projectId, offset, limit)`, `profile(projectId, id)` | `profile.list`, `profile.get` | `project:read` for project |
| `channels(projectId, offset, limit)`, `channel(projectId, name)` | `channel.list`, `channel.get` | `release:read` for project |
| `releases(projectId, offset, limit)`, `release(projectId, releaseId)` | `release.page`, `release.get` | `release:read` for project |
| `job(projectId, jobId)` | `job.get` | `project:read` for project |

A `HostSession` negotiates capabilities at hello. Permissions remain enforced **server-side on every call**, via `permissionAllowed0207` and live trust checks, and revalidated before a successful response is released (`revalidateCapability04312`). Extension scope is enforced independently of permission grants; foreign-project records are filtered again after repository lookup. Revoke is effective on the next call. A global extension requires global grants to enumerate project IDs; a project-scoped installation cannot list other projects.

The job operation returns **status metadata only**; `payload`, `result`, `actorId`, `leaseToken`, `lastError`, and other potentially sensitive fields are never serialized. Jobs without the exact project ID requested return 404. No job creation, modification or cancellation authority is introduced.

`release.page` returns release metadata without potentially large signed manifests; `release(projectId, releaseId)` returns the complete manifest through `release.get`.

List requests use a bounded `offset` / `limit` (1–50, default 20 in Go; maximum offset 1,000,000), deterministic sort and an optional `nextOffset`. The SDK returns immutable typed Java records and checks project identity on decoded responses. All calls retain the existing 3-second client deadline, 1 MiB response bound, Host authentication, network policy, audit and execution deadline. This is not an efficient cursor-based SQL repository API for millions of rows; underlying repository enumeration is still in-memory and cannot yet be considered high-volume pagination.

Example (inside `Extension.start()`):

```java
BackendServices backend = context.runtime().backend();
BackendServices.Project project = backend.project("demo-project");
BackendServices.Page<BackendServices.Profile> profiles = backend.profiles(project.id(), 0, 20);
for (BackendServices.Profile profile : profiles.items()) {
    System.out.println(profile.name() + " / " + profile.loader());
}
```

Declare `project:read` / `release:read` in the signed extension manifest, grant them for the correct scope, then use the negotiated Host capabilities. Missing/revoked grants fail closed; they are **never** replaced by a backend service account. Data writes, job enqueue and privileged release operations are deliberately not exposed under read permissions.

## тесты и ограничения

- `sh sdk/java/core/build.sh test` includes real HTTP calls from Java SDK to an authenticated loopback broker fixture, typed response decoding, permission denial, revoked grants and malformed cross-scope response rejection.
- `go test -race ./internal/extensionhost -run TestJavaBackendServicesBroker0484` runs against the actual Go Host Broker, memory repository with real projects/profiles/channels/releases and durable job; verifies project boundaries, grant revocation and job redaction.
- `.github/workflows/java-backend-services-0484.yml` runs Java 17/21 on Linux/macOS and Go 1.27.3 broker/security suites. External CI must actually execute before the corresponding matrix is claimed passed.

**Release certification:** feature-level Java tests alone do not certify production GA. Full Go 1.27.3 and Java 17/21 jobs, production PostgreSQL migration/upgrade, native signed artifacts and independent release gates inherited from 0.48.0 remain required. Keep the existing production admission gate closed until independently verified.
