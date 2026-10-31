package ru.launcher.bridge.common;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Реестр связей времени выполнения для логического жизненного цикла игрока Launcher
 * -> proxy -> backend. Связи — непрозрачные 256-битные идентификаторы, выданные бэкендом;
 * неверные значения никогда не передаются в сообщения передачи или событий.
 */
public final class BridgePlayerSessionRegistry {
    private final ConcurrentHashMap<String, String> correlations = new ConcurrentHashMap<>();

    public boolean bind(String username, String correlationId) {
        String player = normalizePlayer(username);
        String correlation = normalizeCorrelation(correlationId);
        if (player.isEmpty() || correlation.isEmpty()) return false;
        correlations.put(player, correlation);
        return true;
    }

    public String get(String username) {
        String value = correlations.get(normalizePlayer(username));
        return value == null ? "" : value;
    }

    /** Reject a delayed disconnect when the same Minecraft name has joined with a new ticket. */
    public boolean matches(String username, String expectedCorrelation) {
        String player = normalizePlayer(username);
        String correlation = normalizeCorrelation(expectedCorrelation);
        if (player.isEmpty() || correlation.isEmpty()) return false;
        String active = correlations.get(player);
        return correlation.equals(active);
    }

    public void clear(String username) {
        String player = normalizePlayer(username);
        if (!player.isEmpty()) correlations.remove(player);
    }

    static String normalizePlayer(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    static String normalizeCorrelation(String value) {
        String correlation = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (correlation.length() != 64) return "";
        for (int i = 0; i < correlation.length(); i++) {
            char c = correlation.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return "";
        }
        return correlation;
    }
}
