package ru.launcher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Исполняемые регрессионные тесты сбоев, ACK и аренды на настоящем журнале с fsync. */
public final class BridgeControlJournal0412Test {
    private static int passed;
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }
    private static BridgeControlCommand command(String id, String payloadHash, long seq, String channel, String token) {
        return new BridgeControlCommand("server", id, "runtime", 7L, 1L, "server.maintenance", Map.of("enabled", "true"),
            payloadHash, seq, channel, token, 1, 1L, 2L, "v3", "digest", "pub", "fingerprint", "signature", "", "", "");
    }
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("bridge-wal-0412-");
        Path journalFile = dir.resolve("control.journal");
        BridgeControlCommand action;
        String channel;
        try (BridgeControlJournal j = new BridgeControlJournal(journalFile)) {
            channel = j.channelId("runtime");
            action = command("initial", "a".repeat(64), 1, channel, "lease-token-123456789");
            j.begin(action);
            check("executing".equals(j.state(action).phase()), "начало должно сохранять маркер выполнения");
            boolean concurrentDenied = false;
            try (BridgeControlJournal other = new BridgeControlJournal(journalFile)) { }
            catch (java.io.IOException expected) { concurrentDenied = true; }
            check(concurrentDenied, "второй исполнитель не должен получать журнал");
            boolean duplicateDenied = false;
            try { j.begin(action); } catch (java.io.IOException expected) { duplicateDenied = true; }
            check(duplicateDenied, "re-entry must not repeat the action");
        }
        try (BridgeControlJournal j = new BridgeControlJournal(journalFile)) {
            check("executing".equals(j.state(action).phase()), "сбой до фиксации должен давать неопределённый результат");
            BridgeControlResult unknown = BridgeControlResult.indeterminate("agent died after admission");
            j.complete(action, unknown);
            check(j.unacknowledged("runtime", channel).size() == 1, "восстановление после сбоя должно поставить подтверждение в очередь");
        }
        try (BridgeControlJournal j = new BridgeControlJournal(journalFile)) {
            check(channel.equals(j.channelId("runtime")), "same JVM/runtime must resume its channel");
            var pending = j.unacknowledged("runtime", channel);
            check(pending.size() == 1 && "indeterminate".equals(pending.get(0).result().status()), "потерянное подтверждение должно сохраняться после перезапуска");
            j.acknowledge(pending.get(0));
            check(j.unacknowledged("runtime", channel).isEmpty(), "подтверждение должно сохраняться");
            check(j.acknowledgedSequence() == 1, "подтверждённая контрольная отметка должна сохраняться атомарно");
            check(j.state(action) != null, "подтверждение должно сохранять запись, запрещающую повтор");
            // Ответ потерян ПОСЛЕ реального действия: сохраните результат и повторите только ACK.
            var b = command("second", "b".repeat(64), 2, channel, "lease-token-123456780");
            j.begin(b);
            j.complete(b, BridgeControlResult.verified(Map.of("enabled", "true", "mode", "maintenance")));
            check(j.unacknowledged("runtime", channel).size() == 1, "неподтверждённый результат должен сохраняться в устойчивой очереди");
            boolean replayDenied = false;
            try { j.begin(b); } catch (java.io.IOException expected) { replayDenied = true; }
            check(replayDenied, "even ACK-loss replay cannot execute again");
            boolean digestDenied = false;
            try { j.state(command("second", "f".repeat(64), 2, channel, "lease-token-123456780")); }
            catch (IllegalStateException expected) { digestDenied = true; }
            check(digestDenied, "идентификатор команды с изменёнными данными должен вызывать безопасный отказ");
            for (int i = 3; i < 270; i++) {
                var c = command("c" + i, "a".repeat(64), i, channel, "lease-token-123456780");
                j.begin(c);
                j.complete(c, BridgeControlResult.ok(Map.of()));
            }
            check(j.state(action) != null, "большой журнал должен сохранять старейшую запись о запрете повтора команды");
            String newChannel = j.channelId("another-runtime");
            check(!newChannel.equals(channel) && j.unacknowledged("another-runtime", newChannel).isEmpty(),
                "new JVM runtime must never replay old runtime commands");
        }
        // Обновите реальную дисковую схему 0.41.1 без полей квитанции, не стирая
        // уже выполненную команду и не запуская её снова.
        Path legacy = dir.resolve("legacy.journal");
        java.util.Properties old = new java.util.Properties();
        var oldCommand = command("legacy", "b".repeat(64), 50, channel, "lease-token-legacy123");
        old.setProperty("legacy.digest", oldCommand.digest());
        old.setProperty("legacy.phase", "done");
        old.setProperty("legacy.status", "executed");
        old.setProperty("legacy.result", BridgeControlCommand.encodeMap(Map.of("accepted", "true")));
        old.setProperty("legacy.error", "");
        try (var out = Files.newOutputStream(legacy)) { old.store(out, "0.41.1 journal"); }
        try (BridgeControlJournal migrated = new BridgeControlJournal(legacy)) {
            check("done".equals(migrated.state(oldCommand).phase()), "устаревшая запись о запрете повтора должна читаться без повторного выполнения");
            migrated.bindLegacyReceipt(oldCommand);
            check(migrated.unacknowledged("runtime", channel).size() == 1, "legacy result must be safely ACK-recoverable");
            boolean wrongLeaseDenied = false;
            try { migrated.bindLegacyReceipt(command("legacy", "b".repeat(64), 50, channel, "malicious-new-lease000")); }
            catch (java.io.IOException expected) { wrongLeaseDenied = true; }
            check(wrongLeaseDenied, "нельзя изменять записанную аренду выполнения");
        }
        boolean corruptedDenied = false;
        Files.writeString(journalFile, "\nmalicious=true\n", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
        try (BridgeControlJournal ignored = new BridgeControlJournal(journalFile)) { }
        catch (java.io.IOException expected) { corruptedDenied = true; }
        check(corruptedDenied, "повреждённый журнал должен вызывать безопасный отказ");
        System.out.println("BridgeControlJournal0412: " + passed + " проверок пройдено");
    }
}
