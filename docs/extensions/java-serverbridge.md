# NeverLauncher 0.48.8 — интеграция Java с ServerBridge

Java extensions use `context.runtime().serverBridge()` to access the actual
ServerBridge v3 PostgreSQL repository through the **existing authenticated Go
Extension Host broker**. This is an operational integration, not an alternate
ServerBridge server, raw SQL API, Minecraft auth endpoint or in-process classpath
patch. The SDK is Java 17-compatible, including Java 21 hosts.

## Действующие данные и разрешения

| Java SDK call | Broker operation | Required live permissions |
| --- | --- | --- |
| `serverBridge().servers(projectId, offset, limit)` | `bridge.servers` | `serverbridge:read` |
| `serverBridge().server(projectId, serverId)` | `bridge.server` | `serverbridge:read` |
| `serverBridge().pendingJoinTicket(projectId, serverId, username)` | `bridge.access.ticket` | `serverbridge:read`, `project:read` |
| `serverBridge().command(...)` | `bridge.command.create` | `serverbridge:read`, plus game-domain permission by command type |
| `serverBridge().commandStatus(projectId, serverId, id)` | `bridge.command.get` | `serverbridge:read`, plus game-domain permission by stored command type |
| `serverBridge().subscribeEvents(listener)` | Existing `serverbridge.event.received` EventBus | `events:subscribe`, `serverbridge:read` |

All data reads are scoped to an explicit project ID and to the installation's
scope; listing is capped at 50 entries per request. Broker permissions are
revalidated after data access and before returning a response. Stored node
credential material, public keys, fingerprint hashes, command arguments, actor,
raw lease/ACK tokens, and request digests are not sent to Java code.

**Access check is advisory only.** `pendingJoinTicket()` reports whether there
is a live ticket issued by NeverLauncher for the requested server and player,
bound to the node identity epoch. It DOES NOT authorize login, issue a ticket,
consume a ticket or validate a Mojang/Microsoft identity. Actual admission
still goes exclusively through authenticated ServerBridge `hasJoined` and its
one-time ticket redemption, continuous trust and official Minecraft validation.

## Управление через очередь, без команд ОС

`command()` inserts into the existing ServerBridge v3 durable command store.
Queueing returns `pending` and a command ID; it does not mean the game server
executed the command. Query `commandStatus()` for an authoritative status.

Supported commands and game-domain grants:

- `message.broadcast`: `gameserver:broadcast` (requires `message`)
- `player.kick`, `whitelist.add/remove/enable/disable`, `ban.add/remove`: `gameserver:moderate`
- `server.save`: `gameserver:save`
- `server.maintenance`, `server.drain`: `gameserver:traffic` (requires `enabled: true|false`)

The Go broker rejects `server.console`, `server.shutdown`, arbitrary shell or
host-management commands. It validates command arguments, signed runtime
capabilities, adapter family restrictions, last observed runtime timestamp,
identity epoch and verified integration hash. PostgreSQL fences command
creation against runtime replacement, stores the canonical SHA-256 digest,
ensures server+actor+idempotency-key uniqueness and audits commands. The
idempotency key is mandatory (8–128 characters); expiry is 10–600 seconds,
default 120. Only the existing signed Bridge node can lease and acknowledge a
queued command. The extension cannot fabricate an ACK or delivery credential.

## Java пример

```java
var bridge = context.runtime().serverBridge();
var node = bridge.server("my-project", "my-server");
if (node.runtimeActive()) {
    var receipt = bridge.command(
        "my-project", "my-server", "message.broadcast",
        java.util.Map.of("message", "Server maintenance in 5 minutes"),
        "maintenance-notice-20261102", 120);
    var state = bridge.commandStatus(
        "my-project", "my-server", receipt.command().id());
    // state.status() is a durable queue state, not a synchronous execution result.
}
bridge.subscribeEvents(event -> {
    var payload = event.event();
    // Durable at-least-once delivery; deduplicate external side effects.
    System.out.println(payload.serverId() + ":" + payload.type());
});
```

## Проверка и оставшиеся условия выпуска

Run `sh sdk/java/core/build.sh test`. The new Java suite uses an actual
loopback HTTP server with bearer authentication and capability negotiation,
not a Java mock of `HostSession`. In CI, run the Go broker's authenticated
HTTP tests, payload/fencing tests and preexisting durable PostgreSQL command
integration suite using Go 1.27.3. A full signed-package, Java 17/21 and
real Minecraft adapter integration suite must complete before GA acceptance.
Inherited 0.48.0+ release blockers are not bypassed by this source update.
