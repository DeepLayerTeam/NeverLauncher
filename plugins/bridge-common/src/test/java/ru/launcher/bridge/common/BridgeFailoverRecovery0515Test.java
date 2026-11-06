package ru.launcher.bridge.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Офлайновая регрессия настоящего долговечного журнала и сбоев протокола; без поддельных ACK. */
public final class BridgeFailoverRecovery0515Test {
    private static int assertions;
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        assertions++;
    }
    private static BridgeProtocolNegotiation protocol(boolean eventStream) {
        return new BridgeProtocolNegotiation(BridgeDefaults.PROTOCOL_VERSION,
            eventStream ? List.of(BridgeDefaults.FEATURE_EVENT_STREAM) : List.of(),
            false, Instant.now());
    }
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("bridge-failover-0515-");
        NodeIdentity node = NodeIdentity.loadOrCreate(root.resolve("node.key"));
        Path journal = root.resolve("events.wal");
        String runtime = "a".repeat(64);
        BridgeEventJournal events = new BridgeEventJournal(journal, "server", runtime, node);
        events.append("server.recovered", Map.of("source", "failover"));
        check(events.nextBatch(64).size() == 1, "событие должно быть сохранено в очереди на диске");
        boolean blocked = false;
        try { LauncherApiClient.requireEventStream0515(protocol(false)); }
        catch (IOException expected) { blocked = true; }
        check(blocked, "сервер без потока событий не должен разрешать подтверждение");
        check(events.ackSequence() == 0 && events.nextBatch(64).size() == 1,
            "Узел с ограниченными возможностями должен сохранять подписанное событие на диске");
        // Имитируйте перезагрузку JVM/плагина и повторное подключение Backend без серверного ACK.
        BridgeEventJournal recovered = new BridgeEventJournal(journal, "server", runtime, node);
        check(recovered.nextBatch(64).size() == 1, "потеря HTTP-ответа не должна удалять событие после перезапуска");
        LauncherApiClient.requireEventStream0515(protocol(true));
        check(recovered.ackSequence() == 0, "одно лишь согласование не считается подтверждением");
        recovered.acknowledge(1); // только после проверки фактического подтверждения ACK от Backend
        check(recovered.ackSequence() == 1 && recovered.nextBatch(64).isEmpty(), "настоящее подтверждение сдвигает контрольную точку");
        BridgeEventJournal reloaded = new BridgeEventJournal(journal, "server", runtime, node);
        check(reloaded.ackSequence() == 1 && reloaded.nextBatch(64).isEmpty(), "подтверждение сохраняется после перезапуска");
        System.out.println("BridgeFailoverRecovery0515: " + assertions + " проверок пройдено");
    }
}
