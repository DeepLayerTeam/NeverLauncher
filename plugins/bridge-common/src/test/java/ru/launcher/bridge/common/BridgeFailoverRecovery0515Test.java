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
        check(events.nextBatch(64).size() == 1, "event must be queued to disk");
        boolean blocked = false;
        try { LauncherApiClient.requireEventStream0515(protocol(false)); }
        catch (IOException expected) { blocked = true; }
        check(blocked, "backend without event stream must not authorize ACK");
        check(events.ackSequence() == 0 && events.nextBatch(64).size() == 1,
            "a reduced-capability endpoint must leave the signed event on disk");
        // Имитируйте перезагрузку JVM/плагина и повторное подключение Backend без серверного ACK.
        BridgeEventJournal recovered = new BridgeEventJournal(journal, "server", runtime, node);
        check(recovered.nextBatch(64).size() == 1, "lost HTTP reply must preserve event after restart");
        LauncherApiClient.requireEventStream0515(protocol(true));
        check(recovered.ackSequence() == 0, "negotiation alone is never an ACK");
        recovered.acknowledge(1); // только после проверки фактического подтверждения ACK от Backend
        check(recovered.ackSequence() == 1 && recovered.nextBatch(64).isEmpty(), "real ACK advances checkpoint");
        BridgeEventJournal reloaded = new BridgeEventJournal(journal, "server", runtime, node);
        check(reloaded.ackSequence() == 1 && reloaded.nextBatch(64).isEmpty(), "ACK survives restart");
        System.out.println("BridgeFailoverRecovery0515: " + assertions + " assertions passed");
    }
}
