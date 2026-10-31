package ru.launcher.bridge.common;

import java.util.List;

/** JVM/host integration smoke: observes this *real* Java OS process, not a mock MXBean. */
public final class BridgeLiveTelemetry0419Test {
    public static void main(String[] args) {
        BridgeTelemetrySampler sampler = new BridgeTelemetrySampler();
        BridgeTelemetrySnapshot initial = sampler.sample("real-runtime");
        require(initial.processId() != null && initial.processId() == ProcessHandle.current().pid(), "actual JVM pid");
        require(initial.heapCommittedBytes() >= initial.heapUsedBytes(), "actual heap");
        require(initial.processCpuTimeNanos() == null || initial.processCpuTimeNanos() >= 0, "CPU time");
        if (initial.hostTotalMemoryBytes() != null) {
            require(initial.hostFreeMemoryBytes() != null && initial.hostTotalMemoryBytes() > 0, "host memory availability");
            require(initial.hostFreeMemoryBytes() <= initial.hostTotalMemoryBytes(), "host physical memory");
        }
        // Deliberately future-dated platform observations may not claim a healthy game.
        sampler.recordPlatformSample(new BridgePlatformTelemetry(
            System.currentTimeMillis() + 120_000L, 20.0, 10.0, 42, 100,
            1, null, null, null, false, List.of("server.tick")));
        require(sampler.latestPlatformSample() == null, "reject future platform timestamp");
        BridgeTelemetrySnapshot future = sampler.sample("real-runtime");
        require("unavailable".equals(future.tickHealth()) && future.tps() == null, "future tick is unknown");
        require(future.playersOnline() == null && !future.toJson().contains("\"playersOnline\""), "missing players are not zero");
        // The next valid observation is a real platform reading for the same JVM.
        sampler.recordPlatformSample(BridgePlatformTelemetry.server(20.0, 13.0, 8, 100,
            1, null, 200L, null, false, List.of("server.tick")));
        BridgeTelemetrySnapshot fresh = sampler.sample("real-runtime");
        require("healthy".equals(fresh.tickHealth()) && fresh.playersOnline() == 8, "fresh observed ticks");
        require(fresh.processId().equals(initial.processId()), "same observed OS process");
        require(fresh.toJson().contains("\"processId\":" + ProcessHandle.current().pid()), "signed JSON includes PID");
        System.out.println("PASS 0419 Java process telemetry / stale / future / JSON");
    }
    private static void require(boolean value, String assertion) {
        if (!value) throw new AssertionError(assertion);
    }
}
