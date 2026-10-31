# NeverLauncher 0.42.3 — EventBus, hooks, JVM RPC and durable runtime storage

This release changes **executable behavior**, not protocol identifiers. Host Protocol, Event Protocol and Extension API stay at `1.0`. No new public endpoint or manifest format is required.

## Delivery and subscriber lifecycle

- The Go EventBus records events and deliveries in its existing durable repository. A worker acquires **one lease immediately before each callback**, leaving the remainder of a batch unleased until ready; this prevents idle leases expiring while an earlier callback is running. Callback deadlines use 90% of the lease duration, reserving time for acknowledgement/retry.
- Delivery is **at least once**, not exactly once. Callback handlers must make external effects idempotent by the supplied `event.id`, `idempotencyKey`, or their own transactional state. On failure the existing bounded retry/dead-letter mechanism applies. Restarting the worker does not lose existing pending deliveries.
- `RuntimeEvents.close()` stops **local** Java handlers and keeps the server-side subscription so events produced during normal extension downtime can be queued and resumed on restart. `RuntimeEvents.subscribe(type, mode, ...)` upserts the persisted binding when the JVM starts again. To permanently stop listening, call `RuntimeEvents.unsubscribe(type, mode)` before shutting down. Removing an extension through lifecycle management remains a separate administrative operation; normal shutdown no longer acts as an unsubscribe.
- A stale event with a removed/disabled installation is not delivered by the store; the installed extension and live broker policy remain authoritative. Changing a declared hook between versions may require an explicit unsubscribe/migration; it must not be done implicitly on every JVM stop.

## JVM callback and command limits

- The existing EventBus permits canonical payloads up to 1 MiB. Java `/v1/events` and `/v1/hooks` now accept bounded envelopes **up to 2 MiB**, accommodating the payload plus metadata/escapes. Calls over 2 MiB return HTTP 413. They remain authenticated and loopback-only, with the same bounded handler pool and timeout; event schema validation still runs before extension code.
- Java `/v1/commands` and `/v1/rpc` stay at **64 KiB request/response limits**, including RPC deadline and request-ID verification. Command handlers returning JSON `null` are correctly serialized rather than failing with HTTP 422.
- A synchronous hook that throws returns a non-success response; the Go caller fails closed instead of proceeding with publication. Hook callbacks are never considered successful on a timeout.

## Durable JSON documents

- `runtime.config.*` and `runtime.storage.*` use the existing Go broker on the configured `ExtensionRoot`, isolated by extension ID and scope. Values are validated, atomically renamed on update, and guarded by live `storage:read`/`storage:write` permissions. The service also makes a best-effort directory sync after delete, matching rename behavior. Limits remain 128 KiB per document, 256 documents and 4 MiB per extension/scope.
- This is **node-local filesystem durability**, not a claim of distributed writable storage across multiple independent `ExtensionRoot` hosts. In an HA deployment arrange for consistent ownership and a verified supported storage topology; the per-process mutex does not provide a cross-node quota lock.
- Invalid multi-document JSON event input is rejected rather than silently accepting only its first value.

## Reproducible checks

```sh
sh sdk/java/core/build.sh test
sh examples/extensions/java-runtime/build.sh
python3 examples/extensions/java-runtime/test-runner.py
# Requires project Go 1.27.3, a configured development toolchain and test dependencies:
cd services/api
go test -race -count=1 -run 'Test.*(0206|0423)' ./internal/eventbus ./internal/repository
go test -race -count=1 -run 'TestRuntime.*(0303|0423)' ./internal/extensionhost
```

The JVM tests use real Java processes, authenticated HTTP callbacks, broker operations and typed CLI invocations, including shutdown/restart and re-registration. The Go tests cover durable replay across Bus worker restarts, independent lease acquisition while a callback blocks, invalid JSON rejection, and recovery of on-disk broker documents across restarted Supervisors. **Tests requiring Go 1.27.3 or live PostgreSQL/production release attestations must execute in CI or the intended environment; a Java-only pass is not product-wide certification.**

## Constraints preserved

Do not treat Java extension code as OS-sandboxed or infer Gravit binary compatibility. Full 0.42.3 production release approval still requires the project's current mandatory ServerBridge, signing, target matrix, negative-path and final artifact checks. This patch does not provide those signed acceptance artifacts.
