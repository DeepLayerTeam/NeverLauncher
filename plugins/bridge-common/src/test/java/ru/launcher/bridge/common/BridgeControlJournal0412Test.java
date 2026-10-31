package ru.launcher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Executable crash/ACK/lease/regression tests using an actual fsynced journal. */
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
            check("executing".equals(j.state(action).phase()), "begin must persist execution marker");
            boolean concurrentDenied = false;
            try (BridgeControlJournal other = new BridgeControlJournal(journalFile)) { }
            catch (java.io.IOException expected) { concurrentDenied = true; }
            check(concurrentDenied, "second executor must not acquire the journal");
            boolean duplicateDenied = false;
            try { j.begin(action); } catch (java.io.IOException expected) { duplicateDenied = true; }
            check(duplicateDenied, "re-entry must not repeat the action");
        }
        try (BridgeControlJournal j = new BridgeControlJournal(journalFile)) {
            check("executing".equals(j.state(action).phase()), "crash before commit must be indeterminate");
            BridgeControlResult unknown = BridgeControlResult.indeterminate("agent died after admission");
            j.complete(action, unknown);
            check(j.unacknowledged("runtime", channel).size() == 1, "crash recovery must enqueue an ACK");
        }
        try (BridgeControlJournal j = new BridgeControlJournal(journalFile)) {
            check(channel.equals(j.channelId("runtime")), "same JVM/runtime must resume its channel");
            var pending = j.unacknowledged("runtime", channel);
            check(pending.size() == 1 && "indeterminate".equals(pending.get(0).result().status()), "lost ACK must survive restart");
            j.acknowledge(pending.get(0));
            check(j.unacknowledged("runtime", channel).isEmpty(), "confirmed ACK must persist");
            check(j.acknowledgedSequence() == 1, "confirmed watermark must persist atomically");
            check(j.state(action) != null, "ACK must retain nonreplay tombstone");
            // A response lost AFTER a real action: persist the result; retry only the ACK.
            var b = command("second", "b".repeat(64), 2, channel, "lease-token-123456780");
            j.begin(b);
            j.complete(b, BridgeControlResult.verified(Map.of("enabled", "true", "mode", "maintenance")));
            check(j.unacknowledged("runtime", channel).size() == 1, "unacknowledged result must be durably queued");
            boolean replayDenied = false;
            try { j.begin(b); } catch (java.io.IOException expected) { replayDenied = true; }
            check(replayDenied, "even ACK-loss replay cannot execute again");
            boolean digestDenied = false;
            try { j.state(command("second", "f".repeat(64), 2, channel, "lease-token-123456780")); }
            catch (IllegalStateException expected) { digestDenied = true; }
            check(digestDenied, "command ID with changed payload must fail closed");
            for (int i = 3; i < 270; i++) {
                var c = command("c" + i, "a".repeat(64), i, channel, "lease-token-123456780");
                j.begin(c);
                j.complete(c, BridgeControlResult.ok(Map.of()));
            }
            check(j.state(action) != null, "large journal must retain oldest command tombstone");
            String newChannel = j.channelId("another-runtime");
            check(!newChannel.equals(channel) && j.unacknowledged("another-runtime", newChannel).isEmpty(),
                "new JVM runtime must never replay old runtime commands");
        }
        // Upgrade the actual 0.41.1 on-disk schema (which had no receipt fields)
        // without erasing the already-executed command or invoking it again.
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
            check("done".equals(migrated.state(oldCommand).phase()), "legacy tombstone must be read without replay");
            migrated.bindLegacyReceipt(oldCommand);
            check(migrated.unacknowledged("runtime", channel).size() == 1, "legacy result must be safely ACK-recoverable");
            boolean wrongLeaseDenied = false;
            try { migrated.bindLegacyReceipt(command("legacy", "b".repeat(64), 50, channel, "malicious-new-lease000")); }
            catch (java.io.IOException expected) { wrongLeaseDenied = true; }
            check(wrongLeaseDenied, "cannot change a recorded execution lease");
        }
        boolean corruptedDenied = false;
        Files.writeString(journalFile, "\nmalicious=true\n", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
        try (BridgeControlJournal ignored = new BridgeControlJournal(journalFile)) { }
        catch (java.io.IOException expected) { corruptedDenied = true; }
        check(corruptedDenied, "corrupt journal must fail closed");
        System.out.println("BridgeControlJournal0412: " + passed + " assertions passed");
    }
}
