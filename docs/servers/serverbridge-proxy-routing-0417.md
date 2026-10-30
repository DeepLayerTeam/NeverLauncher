# ServerBridge 0.41.7 — live proxy routing

## Execution path

1. The Velocity/BungeeCord/Waterfall adapter requires an authenticated Minecraft UUID on the proxy (`confirmAuthenticatedPlayer`). Transfers without an authenticated session fail closed.
2. The production API client requests the signed node-authenticated `GET /api/v1/server-bridge/servers/{id}/routes` endpoint (when routing-v2 is negotiated). It parses the actual `data.items` array rather than searching JSON text for an arbitrary node name. The source ID, route/runtime IDs, revision, state, health, capacity and freshness are validated. Invalid, duplicate, expired, full, drained and maintenance routes fail closed.
3. The same client calls `POST /api/v1/server-bridge/handoff` **once**, never retrying an uncertain POST. Backend/PostgreSQL re-checks current source and target runtime, topology and reserved slots and issues a single-use handoff. The target server consumes the handoff during join. A route check alone never authorizes a join.
4. Proxy-native connection attempts are bound to one pending handoff per player. A changed registered destination after authorization fails closed; no automatic fallback to a different backend is attempted under the same ticket.
5. `proxy.connect`/`proxy.switch` is emitted **after** the proxy reports a real server connection (`ServerConnectedEvent`), never merely after ticket creation. Failed switches do not generate false success events; the previously connected player is not disconnected by the plugin on ordinary handoff denial.

## Platform specifics

- **Velocity:** preserves asynchronous pre-connect authorization, handles prior plugin deny/redirect results, reserves one transfer until successful connection or ticket expiration, fences stale async completions, and compares registered target identity before allowing the actual connect.
- **BungeeCord/Waterfall:** shares one production plugin; cancels the initial synchronous connect event, authorizes asynchronously, reconnects through the Bungee player API with a one-time prepared handoff bypass, prevents parallel attempts by the same player and verifies the player/session and registered target before connecting. `ServerConnectedEvent` reports observed successful backend connections.
- **Quilt/Sponge:** inbound join validation exists in the 0.41.6 adapters, so the Backend routing store now includes these kinds in allowed backends and topology joins. **Vanilla RCON sidecar is not routable:** it cannot enforce inbound one-time join handoffs on the game-server socket.

## Operational boundaries

- Stale or unreachable Backend returns a deny; not a guessed local routing result. Available targets depend on fresh signed routing snapshots and PostgreSQL state.
- No transparent retry of a one-time handoff when the Backend response is lost. A separately initiated later player request may obtain a new handoff after the prior in-flight operation is settled/expired.
- Server plugin load order can influence event ordering. Target-side handoff redemption is the ultimate authorization barrier even if another proxy plugin redirects after this bridge's pre-connect event.
- Existing player sessions on a drained backend remain attached until another explicit transfer. Draining blocks **new** transfers; it does not force evictions.

## Verification

Run `bash e2e/scripts/test-proxy-routing-0417.sh` with OpenJDK 21. Tests compile the actual shared ServerBridge/Proxy runtime source and exercise parsed route responses, stale/capacity/health scenarios, forged/duplicate JSON and existing auth/journal regressions.

**Not certified here:** actual Velocity, BungeeCord or Waterfall JAR execution, simultaneous proxy plugins, true cross-server Minecraft client transfer and PostgreSQL failover. These require upstream platform artifacts and a live E2E environment; Java parser tests are not substitutes.
