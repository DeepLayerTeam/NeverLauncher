package ru.neverlauncher.bridge.common;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Ограниченный сборщик телеметрии ServerBridge. Метрики JVM считываются один раз
 * за heartbeat. Адаптеры публикуют неизменяемые образцы в AtomicReference из
 * безопасного для их API потока; HTTP-поток никогда не перечисляет миры или сущности.
 */
public final class BridgeTelemetrySampler {
    private static final long PLATFORM_SAMPLE_MAX_AGE_MS = 90_000L;
    // A clock-skewed or future-dated platform sample must never make the game healthy.
    private static final long PLATFORM_FUTURE_SKEW_MS = 5_000L;

    private final MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
    private final ThreadMXBean threads = ManagementFactory.getThreadMXBean();
    private final List<GarbageCollectorMXBean> collectors = List.copyOf(ManagementFactory.getGarbageCollectorMXBeans());
    private final AtomicReference<BridgePlatformTelemetry> platform = new AtomicReference<>();
    private final AtomicLong sequence = new AtomicLong();
    private final AtomicLong previousGcCollections = new AtomicLong(-1L);
    private final AtomicLong previousGcTime = new AtomicLong(-1L);
    private final AtomicLong previousSampleAt = new AtomicLong(0L);

    public void recordPlatformSample(BridgePlatformTelemetry sample) {
        if (sample != null) platform.set(sample);
    }

    public BridgePlatformTelemetry latestPlatformSample() {
        BridgePlatformTelemetry sample = platform.get();
        if (sample == null) return null;
        long age = System.currentTimeMillis() - sample.sampledAtUnixMillis();
        if (age > PLATFORM_SAMPLE_MAX_AGE_MS || age < -PLATFORM_FUTURE_SKEW_MS) return null;
        return sample;
    }

    public BridgeTelemetrySnapshot sample(String runtimeId) {
        long now = System.currentTimeMillis();
        long previousAt = previousSampleAt.getAndSet(now);
        long window = previousAt <= 0L ? 0L : Math.max(0L, Math.min(600_000L, now - previousAt));

        BridgePlatformTelemetry game = platform.get();
        if (game != null && (now - game.sampledAtUnixMillis() > PLATFORM_SAMPLE_MAX_AGE_MS ||
            now - game.sampledAtUnixMillis() < -PLATFORM_FUTURE_SKEW_MS)) game = null;

        MemoryUsage heap = memory.getHeapMemoryUsage();
        MemoryUsage nonHeap = memory.getNonHeapMemoryUsage();
        long gcCount = 0L;
        long gcTime = 0L;
        for (GarbageCollectorMXBean collector : collectors) {
            long count = collector.getCollectionCount();
            long time = collector.getCollectionTime();
            if (count > 0L) gcCount += count;
            if (time > 0L) gcTime += time;
        }
        long oldCount = previousGcCollections.getAndSet(gcCount);
        long oldTime = previousGcTime.getAndSet(gcTime);
        long gcCountDelta = oldCount < 0L ? 0L : Math.max(0L, gcCount - oldCount);
        long gcTimeDelta = oldTime < 0L ? 0L : Math.max(0L, gcTime - oldTime);

        Double tps = game == null ? null : game.tps();
        Double mspt = game == null ? null : game.mspt();
        String health = tickHealth(tps, mspt, game != null);
        LinkedHashSet<String> metrics = new LinkedHashSet<>();
        metrics.add("jvm.heap");
        metrics.add("jvm.nonheap");
        metrics.add("jvm.gc");
        metrics.add("jvm.threads");
        if (game != null) metrics.addAll(game.metrics());
        Long pid = ProcessHandle.current().pid();
        Long processCpuNanos = null;
        Double processCpuLoad = null;
        Long hostTotalMemory = null;
        Long hostFreeMemory = null;
        java.lang.management.OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        if (os instanceof com.sun.management.OperatingSystemMXBean extended) {
            long cpu = extended.getProcessCpuTime();
            if (cpu >= 0) { processCpuNanos = cpu; metrics.add("jvm.process_cpu_time"); }
            double load = extended.getProcessCpuLoad();
            if (Double.isFinite(load) && load >= 0 && load <= 1) {
                processCpuLoad = load; metrics.add("jvm.process_cpu_load");
            }
            long total = extended.getTotalMemorySize();
            long free = extended.getFreeMemorySize();
            if (total > 0 && free >= 0 && free <= total) {
                hostTotalMemory = total; hostFreeMemory = free; metrics.add("host.memory");
            }
        }
        metrics.add("jvm.process_id");

        return new BridgeTelemetrySnapshot(
            Math.max(1L, sequence.incrementAndGet()),
            now,
            window,
            runtimeId == null ? "" : runtimeId,
            tps,
            mspt,
            health,
            game == null ? null : game.playersOnline(),
            game == null ? null : game.playersMax(),
            nonNegative(heap.getUsed()),
            nonNegative(heap.getCommitted()),
            nonNegative(heap.getMax()),
            nonNegative(nonHeap.getUsed()),
            nonNegative(nonHeap.getCommitted()),
            gcCount,
            gcTime,
            gcCountDelta,
            gcTimeDelta,
            Math.max(0, threads.getThreadCount()),
            Math.max(0, threads.getDaemonThreadCount()),
            Math.max(0, threads.getPeakThreadCount()),
            game == null ? null : game.loadedWorlds(),
            game == null ? null : game.loadedDimensions(),
            game == null ? null : game.loadedChunks(),
            game == null ? null : game.entityCount(),
            game != null && game.samplingBudgetExceeded(),
            List.copyOf(metrics),
            pid, processCpuNanos, processCpuLoad, hostTotalMemory, hostFreeMemory
        );
    }

    private static String tickHealth(Double tps, Double mspt, boolean platformPresent) {
        if (!platformPresent || (tps == null && mspt == null)) return "unavailable";
        if ((mspt != null && mspt >= 50.0d) || (tps != null && tps < 15.0d)) return "overloaded";
        if ((mspt != null && mspt >= 40.0d) || (tps != null && tps < 19.0d)) return "degraded";
        return "healthy";
    }

    private static long nonNegative(long value) {
        return value < 0L ? 0L : value;
    }
}
