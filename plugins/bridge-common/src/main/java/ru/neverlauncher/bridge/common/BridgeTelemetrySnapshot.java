package ru.neverlauncher.bridge.common;

import java.util.ArrayList;
import java.util.List;

/** Сетевой снимок для ServerBridge Протокол v3 телеметрия.v1. */
public record BridgeTelemetrySnapshot(
    long sequence,
    long sampledAtUnixMillis,
    long windowMillis,
    String runtimeId,
    Double tps,
    Double mspt,
    String tickHealth,
    int playersOnline,
    int playersMax,
    long heapUsedBytes,
    long heapCommittedBytes,
    long heapMaxBytes,
    long nonHeapUsedBytes,
    long nonHeapCommittedBytes,
    long gcCollections,
    long gcCollectionTimeMillis,
    long gcCollectionsDelta,
    long gcCollectionTimeDeltaMillis,
    int threadCount,
    int daemonThreadCount,
    int peakThreadCount,
    Integer loadedWorlds,
    Integer loadedDimensions,
    Long loadedChunks,
    Long entityCount,
    boolean samplingBudgetExceeded,
    List<String> metrics
) {
    public String toJson() {
        StringBuilder out = new StringBuilder(512);
        out.append('{')
            .append("\"sequence\":").append(sequence)
            .append(",\"sampledAtUnixMillis\":").append(sampledAtUnixMillis)
            .append(",\"windowMillis\":").append(windowMillis)
            .append(",\"runtimeId\":").append(quote(runtimeId))
            .append(",\"tickHealth\":").append(quote(tickHealth))
            .append(",\"playersOnline\":").append(playersOnline)
            .append(",\"playersMax\":").append(playersMax)
            .append(",\"heapUsedBytes\":").append(heapUsedBytes)
            .append(",\"heapCommittedBytes\":").append(heapCommittedBytes)
            .append(",\"heapMaxBytes\":").append(heapMaxBytes)
            .append(",\"nonHeapUsedBytes\":").append(nonHeapUsedBytes)
            .append(",\"nonHeapCommittedBytes\":").append(nonHeapCommittedBytes)
            .append(",\"gcCollections\":").append(gcCollections)
            .append(",\"gcCollectionTimeMillis\":").append(gcCollectionTimeMillis)
            .append(",\"gcCollectionsDelta\":").append(gcCollectionsDelta)
            .append(",\"gcCollectionTimeDeltaMillis\":").append(gcCollectionTimeDeltaMillis)
            .append(",\"threadCount\":").append(threadCount)
            .append(",\"daemonThreadCount\":").append(daemonThreadCount)
            .append(",\"peakThreadCount\":").append(peakThreadCount)
            .append(",\"samplingBudgetExceeded\":").append(samplingBudgetExceeded);
        appendDouble(out, "tps", tps);
        appendDouble(out, "mspt", mspt);
        appendInt(out, "loadedWorlds", loadedWorlds);
        appendInt(out, "loadedDimensions", loadedDimensions);
        appendLong(out, "loadedChunks", loadedChunks);
        appendLong(out, "entityCount", entityCount);
        out.append(",\"metrics\":").append(jsonArray(metrics)).append('}');
        return out.toString();
    }

    private static void appendDouble(StringBuilder out, String name, Double value) {
        if (value != null && Double.isFinite(value)) out.append(',').append(quote(name)).append(':').append(value);
    }

    private static void appendInt(StringBuilder out, String name, Integer value) {
        if (value != null) out.append(',').append(quote(name)).append(':').append(value);
    }

    private static void appendLong(StringBuilder out, String name, Long value) {
        if (value != null) out.append(',').append(quote(name)).append(':').append(value);
    }

    private static String jsonArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        if (values != null) {
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) out.append(',');
                out.append(quote(values.get(i)));
            }
        }
        return out.append(']').toString();
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
