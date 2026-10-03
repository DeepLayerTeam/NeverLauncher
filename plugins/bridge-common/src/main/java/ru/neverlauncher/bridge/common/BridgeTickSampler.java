package ru.neverlauncher.bridge.common;

/**
 * Fixed-memory tick sampler. It records at most 1,200 server ticks (about one
 * minute at 20 TPS) and therefore cannot grow with server uptime.
 */
public final class BridgeTickSampler {
    private static final int CAPACITY = 1200;
    private final double[] workMillis = new double[CAPACITY];
    private final double[] periodMillis = new double[CAPACITY];
    private int cursor;
    private int size;
    private long currentTickStart;
    private long previousTickStart;

    public synchronized void onTickStart() {
        long now = System.nanoTime();
        currentTickStart = now;
        if (previousTickStart == 0L) previousTickStart = now;
    }

    public synchronized void onTickEnd() {
        long now = System.nanoTime();
        long start = currentTickStart;
        if (start <= 0L) return;
        double work = Math.max(0.0d, (now - start) / 1_000_000.0d);
        double period = previousTickStart <= 0L ? 50.0d : Math.max(0.1d, (start - previousTickStart) / 1_000_000.0d);
        workMillis[cursor] = Math.min(work, 600_000.0d);
        periodMillis[cursor] = Math.min(period, 600_000.0d);
        cursor = (cursor + 1) % CAPACITY;
        if (size < CAPACITY) size++;
        previousTickStart = start;
        currentTickStart = 0L;
    }

    public synchronized TickMetrics snapshot() {
        if (size == 0) return new TickMetrics(null, null, 0);
        double workTotal = 0.0d;
        double periodTotal = 0.0d;
        for (int i = 0; i < size; i++) {
            workTotal += workMillis[i];
            periodTotal += periodMillis[i];
        }
        double avgWork = workTotal / size;
        double avgPeriod = periodTotal / size;
        double tps = avgPeriod <= 0.0d ? 20.0d : Math.min(20.0d, 1000.0d / avgPeriod);
        return new TickMetrics(round3(tps), round3(avgWork), size);
    }

    public record TickMetrics(Double tps, Double mspt, int sampledTicks) {}

    private static double round3(double value) {
        return Math.round(value * 1000.0d) / 1000.0d;
    }
}
