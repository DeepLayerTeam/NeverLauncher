package ru.neverlauncher.bridge.common;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Среда выполнения корреляция реестр для logical NeverLauncher -> прокси -> серверная часть
 * игрок жизненный цикл. Корреляция являются непрозрачный серверная часть-выданный 256-бит identifiers;
 * недопустимый значения являются никогда распространять в handoff/event трафик.
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
