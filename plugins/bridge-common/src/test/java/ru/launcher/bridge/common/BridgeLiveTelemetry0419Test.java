package ru.launcher.bridge.common;

import java.util.List;

/** Дымовой интеграционный тест JVM-хоста наблюдает НАСТОЯЩИЙ процесс Java в ОС, а не имитацию MXBean. */
public final class BridgeLiveTelemetry0419Test {
    public static void main(String[] args) {
        BridgeTelemetrySampler sampler = new BridgeTelemetrySampler();
        BridgeTelemetrySnapshot initial = sampler.sample("real-runtime");
        require(initial.processId() != null && initial.processId() == ProcessHandle.current().pid(), "настоящий идентификатор процесса JVM");
        require(initial.heapCommittedBytes() >= initial.heapUsedBytes(), "настоящая куча памяти");
        require(initial.processCpuTimeNanos() == null || initial.processCpuTimeNanos() >= 0, "CPU time");
        if (initial.hostTotalMemoryBytes() != null) {
            require(initial.hostFreeMemoryBytes() != null && initial.hostTotalMemoryBytes() > 0, "доступная память хоста");
            require(initial.hostFreeMemoryBytes() <= initial.hostTotalMemoryBytes(), "физическая память хоста");
        }
        // Наблюдения платформы с намеренно будущими датами не могут подтверждать здоровье игры.
        sampler.recordPlatformSample(new BridgePlatformTelemetry(
            System.currentTimeMillis() + 120_000L, 20.0, 10.0, 42, 100,
            1, null, null, null, false, List.of("server.tick")));
        require(sampler.latestPlatformSample() == null, "метка времени платформы из будущего отклоняется");
        BridgeTelemetrySnapshot future = sampler.sample("real-runtime");
        require("unavailable".equals(future.tickHealth()) && future.tps() == null, "будущий такт не определён");
        require(future.playersOnline() == null && !future.toJson().contains("\"playersOnline\""), "отсутствие данных об игроках не эквивалентно нулю");
        // Следующее корректное наблюдение — настоящее показание платформы для той же JVM.
        sampler.recordPlatformSample(BridgePlatformTelemetry.server(20.0, 13.0, 8, 100,
            1, null, 200L, null, false, List.of("server.tick")));
        BridgeTelemetrySnapshot fresh = sampler.sample("real-runtime");
        require("healthy".equals(fresh.tickHealth()) && fresh.playersOnline() == 8, "актуальные наблюдаемые такты");
        require(fresh.processId().equals(initial.processId()), "тот же наблюдаемый процесс ОС");
        require(fresh.toJson().contains("\"processId\":" + ProcessHandle.current().pid()), "подписанный JSON содержит идентификатор процесса");
        System.out.println("PASS 0419 Java process telemetry / stale / future / JSON");
    }
    private static void require(boolean value, String assertion) {
        if (!value) throw new AssertionError(assertion);
    }
}
