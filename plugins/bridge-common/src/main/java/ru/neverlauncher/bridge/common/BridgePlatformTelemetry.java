package ru.neverlauncher.bridge.common;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Thread-safe value object produced by a platform adapter on a thread where its
 * Minecraft/proxy API may safely be queried. The HTTP heartbeat never calls
 * platform APIs directly; it only consumes the latest immutable snapshot.
 */
public record BridgePlatformTelemetry(
    long sampledAtUnixMillis,
    Double tps,
    Double mspt,
    int playersOnline,
    int playersMax,
    Integer loadedWorlds,
    Integer loadedDimensions,
    Long loadedChunks,
    Long entityCount,
    boolean samplingBudgetExceeded,
    List<String> metrics
) {
    public BridgePlatformTelemetry {
        if (sampledAtUnixMillis <= 0) sampledAtUnixMillis = System.currentTimeMillis();
        tps = finiteOrNull(tps, 0.0d, 1000.0d);
        mspt = finiteOrNull(mspt, 0.0d, 600_000.0d);
        playersOnline = clamp(playersOnline, 0, 1_000_000);
        playersMax = clamp(playersMax, 0, 1_000_000);
        if (playersMax > 0 && playersOnline > playersMax) playersMax = playersOnline;
        loadedWorlds = boundedInteger(loadedWorlds, 0, 100_000);
        loadedDimensions = boundedInteger(loadedDimensions, 0, 100_000);
        loadedChunks = boundedLong(loadedChunks, 0L, 1_000_000_000L);
        entityCount = boundedLong(entityCount, 0L, 1_000_000_000L);
        LinkedHashSet<String> clean = new LinkedHashSet<>();
        if (metrics != null) {
            for (String value : metrics) {
                if (value == null) continue;
                value = value.trim().toLowerCase(Locale.ROOT);
                if (!value.isEmpty() && value.length() <= 96 && !value.contains("\n") && !value.contains("\r") && !value.contains("\0")) {
                    clean.add(value);
                }
                if (clean.size() >= 32) break;
            }
        }
        metrics = List.copyOf(clean);
    }

    public static BridgePlatformTelemetry proxy(int playersOnline, int playersMax, List<String> metrics) {
        return new BridgePlatformTelemetry(
            System.currentTimeMillis(), null, null,
            playersOnline, playersMax,
            null, null, null, null,
            false, metrics
        );
    }

    public static BridgePlatformTelemetry server(
        Double tps,
        Double mspt,
        int playersOnline,
        int playersMax,
        Integer loadedWorlds,
        Integer loadedDimensions,
        Long loadedChunks,
        Long entityCount,
        boolean budgetExceeded,
        List<String> metrics
    ) {
        return new BridgePlatformTelemetry(
            System.currentTimeMillis(), tps, mspt,
            playersOnline, playersMax,
            loadedWorlds, loadedDimensions, loadedChunks, entityCount,
            budgetExceeded, metrics
        );
    }

    public BridgePlatformTelemetry withTickMetrics(Double newTps, Double newMspt) {
        ArrayList<String> values = new ArrayList<>(metrics);
        if (newTps != null) values.add("tps");
        if (newMspt != null) values.add("mspt");
        return new BridgePlatformTelemetry(
            sampledAtUnixMillis, newTps, newMspt,
            playersOnline, playersMax, loadedWorlds, loadedDimensions,
            loadedChunks, entityCount, samplingBudgetExceeded, values
        );
    }

    private static Double finiteOrNull(Double value, double min, double max) {
        if (value == null || !Double.isFinite(value)) return null;
        return Math.max(min, Math.min(max, value));
    }

    private static Integer boundedInteger(Integer value, int min, int max) {
        if (value == null) return null;
        return Math.max(min, Math.min(max, value));
    }

    private static Long boundedLong(Long value, long min, long max) {
        if (value == null) return null;
        return Math.max(min, Math.min(max, value));
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
