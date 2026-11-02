# NeverLauncher 0.48.7 — Advanced Java Events and Hooks

The real Go EventBus remains the single source of truth for subscription state,
leased deliveries, event ordering, publication idempotency, exponential retry,
and PostgreSQL-backed dead-letter entries. Java modules **do not create a second
queue** and cannot bypass project grants, signing or the core mutation routes.

## JVM SDK usage

```java
services.events().subscribeJob("project.saved", projectSchema,
    payload -> Json.object(payload), event -> {
        // Optional immutable metadata: event.metadata().sequence(),
        // event.metadata().schemaVersion(), event.metadata().orderingKey().
        // Persist an idempotency record together with your external side effect.
        // Throw IOException for retryable failures.
        if (temporarilyUnavailable()) throw new IOException("retry later");
        if (permanentlyInvalid(event.event().payload()))
            throw new RuntimeEvents.PermanentFailure("invalid work item");
        applyChange(event.event().idempotencyKey(), event.event().payload());
    });
services.events().subscribeHook("release.before-publish", releaseSchema,
    payload -> Json.object(payload), event ->
        isPermitted(event.event().payload())
            ? RuntimeEvents.HookDecision.allow()
            : RuntimeEvents.HookDecision.deny("release policy rejected"));
```

`subscribeJob()` is a durable **event-triggered async task consumer**, not a
new arbitrary job-scheduling API. Host callback processing is bounded and
retries occur only after the callback fails/does not ACK. Failure semantics:

- `200 {"accepted":true}`: the Go supervisor checks the JSON acknowledgement
  and rechecks extension authorization before ACKing the leased delivery.
- `503 {"code":"EVENT_RETRY"}`: temporary handler failure; the Go worker
  schedules exponential retry, then dead-letters after its configured limit.
- `422 {"code":"EVENT_REJECTED"}`: the handler explicitly declares work
  permanently invalid (`PermanentFailure`) or the event cannot be decoded;
  the Go worker sends it directly to dead-letter, preserving its event and
  attempt metadata. Other 4xx/5xx codes do not silently become ACK.
- Sync hooks require an explicit `HookDecision.allow()`. A deny, null,
  exception, timeout, missing callback, revoked permission or malformed
  response must abort the protected core operation.

Both publishers and handlers must use stable idempotency keys. The bus provides
**at-least-once delivery**, not exactly-once external effects. A callback can
commit an external side effect and crash before the Go ACK; consumers must
commit their own deduplication record in the **same transactional boundary**
as the external effect (or use a remote idempotency key). SDK-local process
memory is not a durable deduplication mechanism. Dispatch is bounded by the
existing Host timeout, queue, leasing and process limits. Subscription removal
is explicit; lifecycle shutdown retains the pending durable backlog.

Existing `subscribe(eventType,mode,...)` listeners remain source/binary
compatible, while new handlers can read `DetailedEnvelope` metadata. The
protocol remains `1.0`; new Java error codes only add status detail, and
legacy Java callbacks using `accepted:true` continue to work.

## Validation and admission

Run `sh sdk/java/core/build.sh test` with Java 17 and 21 and run the Go
`./internal/eventbus` and `./internal/extensionhost` suites using Go 1.27.3.
Test the actual PostgreSQL lease/retry/dead-letter store, project permissions,
callback loss/restart, signing and Minecraft release publication separately.
This patch is **not** independent GA certification. Historical 0.48.0
PostgreSQL cutover and release gates remain in force.
