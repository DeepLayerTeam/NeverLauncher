package ru.neverlauncher.bridge.common;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Correlates a requested kick with the exact Minecraft session's native quit event. */
public final class KickConfirmations implements AutoCloseable {
    private record Pending(UUID session, CompletableFuture<Boolean> quit) {}
    private final ConcurrentHashMap<String, Pending> pending = new ConcurrentHashMap<>();
    private volatile boolean closed;

    public boolean begin(String username, UUID session) {
        if (closed || username == null || session == null) return false;
        return pending.putIfAbsent(normalize(username), new Pending(session, new CompletableFuture<>())) == null;
    }

    public void observedQuit(String username, String session) {
        if (username == null || session == null) return;
        UUID uuid;
        try { uuid = UUID.fromString(session); } catch (IllegalArgumentException e) { return; }
        Pending state = pending.get(normalize(username));
        if (state != null && state.session().equals(uuid)) state.quit().complete(true);
    }

    public void cancel(String username) {
        if (username == null) return;
        Pending state = pending.remove(normalize(username));
        if (state != null) state.quit().complete(false);
    }

    public BridgeControlResult await(String username, String session, long timeoutMs) throws InterruptedException {
        UUID uuid;
        try { uuid = UUID.fromString(session); } catch (RuntimeException e) { return BridgeControlResult.ok(Map.of("username", username)); }
        String key = normalize(username);
        Pending state = pending.get(key);
        if (state == null || !state.session().equals(uuid)) return BridgeControlResult.ok(Map.of("username", username));
        try {
            if (state.quit().get(timeoutMs, TimeUnit.MILLISECONDS)) {
                return new BridgeControlResult("succeeded", Map.of("username", username, "uuid", uuid.toString(), "online", "false", "verification", "player-quit-event"), "");
            }
        } catch (TimeoutException | java.util.concurrent.ExecutionException ignored) {
            // Dispatch returned, but no correlated native quit event has arrived.
        } finally { pending.remove(key, state); }
        return BridgeControlResult.ok(Map.of("username", username, "uuid", uuid.toString()));
    }

    private static String normalize(String username) { return username.trim().toLowerCase(Locale.ROOT); }
    @Override public void close() {
        closed = true;
        pending.forEach((key, value) -> value.quit().complete(false));
        pending.clear();
    }
}
