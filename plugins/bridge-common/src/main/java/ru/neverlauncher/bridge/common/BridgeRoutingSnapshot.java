package ru.neverlauncher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Подписанный привязанный к среде выполнения маршрутизация advertisement используется через Топология и Маршрутизация 2.
 *  узел ключ подписывает точный state/capacity/health tuple так серверная часть никогда
 * доверие неподписанный маршрут состояние carried через прокси или сервер сигнал состояния.
 */
public record BridgeRoutingSnapshot(
    String runtimeId,
    long observedAtUnixMillis,
    String state,
    boolean acceptingConnections,
    int playersOnline,
    int capacityMax,
    String health,
    String digest,
    String signature
) {
    private static final String SCHEME = "NeverLauncher-ServerBridge-Routing-v2";

    public static BridgeRoutingSnapshot create(
        String serverId,
        String runtimeId,
        String state,
        int playersOnline,
        int capacityMax,
        String health,
        NodeIdentity identity
    ) throws GeneralSecurityException {
        long observed = System.currentTimeMillis();
        String normalizedState = normalizeState(state);
        String normalizedHealth = normalizeHealth(health);
        int online = Math.max(0, Math.min(1_000_000, playersOnline));
        int capacity = Math.max(0, Math.min(1_000_000, capacityMax));
        if (capacity > 0 && online > capacity) capacity = online;
        boolean accepting = "ready".equals(normalizedState)
            && !"unhealthy".equals(normalizedHealth)
            && (capacity == 0 || online < capacity);
        String canonical = canonical(serverId, runtimeId, observed, normalizedState, accepting, online, capacity, normalizedHealth);
        byte[] digestBytes = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        return new BridgeRoutingSnapshot(
            runtimeId == null ? "" : runtimeId.toLowerCase(), observed, normalizedState, accepting, online, capacity,
            normalizedHealth, HexFormat.of().formatHex(digestBytes),
            Base64.getUrlEncoder().withoutPadding().encodeToString(identity.sign(canonical))
        );
    }

    public String toJson() {
        return "{" +
            "\"runtimeId\":" + quote(runtimeId) + "," +
            "\"observedAtUnixMillis\":" + observedAtUnixMillis + "," +
            "\"state\":" + quote(state) + "," +
            "\"acceptingConnections\":" + acceptingConnections + "," +
            "\"playersOnline\":" + playersOnline + "," +
            "\"capacityMax\":" + capacityMax + "," +
            "\"health\":" + quote(health) + "," +
            "\"signature\":" + quote(signature) + "}";
    }

    static String canonical(String serverId, String runtimeId, long observed, String state, boolean accepting, int online, int capacity, String health) {
        return String.join("\n",
            SCHEME,
            b64(serverId),
            runtimeId == null ? "" : runtimeId.trim().toLowerCase(),
            Long.toString(observed),
            normalizeState(state),
            Boolean.toString(accepting),
            Integer.toString(online),
            Integer.toString(capacity),
            normalizeHealth(health)
        );
    }

    private static String normalizeState(String value) {
        value = value == null ? "ready" : value.trim().toLowerCase();
        return switch (value) {
            case "maintenance", "draining" -> value;
            default -> "ready";
        };
    }

    private static String normalizeHealth(String value) {
        value = value == null ? "unhealthy" : value.trim().toLowerCase();
        return switch (value) {
            case "healthy", "degraded" -> value;
            default -> "unhealthy";
        };
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString((value == null ? "" : value.trim()).getBytes(StandardCharsets.UTF_8));
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
