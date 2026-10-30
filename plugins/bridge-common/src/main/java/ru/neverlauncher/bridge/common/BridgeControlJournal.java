package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

/**
 * Durable, single-writer, fail-closed WAL for side-effecting ServerBridge commands.
 * Entries are never discarded: a previously executed command must remain a tombstone
 * even after the Backend has acknowledged it and even after the channel is rotated.
 */
final class BridgeControlJournal implements AutoCloseable {
    record State(String digest, String phase, BridgeControlResult result) {}
    record Receipt(String commandId, String runtimeId, long sequence, String channelId,
                   String leaseToken, BridgeControlResult result) {}
    private static final String CHECKSUM = "_journal.sha256";
    private final Path path;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private final Properties props = new Properties();
    private boolean closed;
    private boolean poisoned;

    BridgeControlJournal(Path path) throws IOException {
        this.path = path.toAbsolutePath().normalize();
        Path parent = this.path.getParent();
        if (parent == null) throw new IOException("journal needs a parent directory");
        Files.createDirectories(parent);
        Path lockPath = this.path.resolveSibling(this.path.getFileName() + ".lock");
        if (Files.isSymbolicLink(lockPath) || Files.isSymbolicLink(this.path))
            throw new IOException("symbolic control journal/lock is forbidden");
        FileChannel opened = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired = null;
        try {
            try { acquired = opened.tryLock(); }
            catch (OverlappingFileLockException e) { throw new IOException("control journal already owned by another agent", e); }
            if (acquired == null) throw new IOException("control journal already owned by another agent");
            setOwnerOnly(lockPath);
            if (Files.exists(this.path, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.size(this.path) == 0) throw new IOException("empty control journal: refuse to forget executed commands");
                try (var in = Files.newInputStream(this.path, LinkOption.NOFOLLOW_LINKS)) {
                    props.load(in);
                } catch (IllegalArgumentException e) {
                    throw new IOException("invalid control journal", e);
                }
                String expected = props.getProperty(CHECKSUM);
                // The unsealed 0.41.1 journal is upgraded on its next durable write.
                if (expected != null && !expected.equalsIgnoreCase(digest(props)))
                    throw new IOException("control journal checksum mismatch: refuse to replay commands");
            }
        } catch (IOException | RuntimeException e) {
            if (acquired != null) acquired.release();
            opened.close();
            throw e;
        }
        lockChannel = opened;
        lock = acquired;
    }

    synchronized String channelId(String runtimeId) throws IOException {
        ensureOpen();
        String normalized = runtimeId == null ? "" : runtimeId.trim().toLowerCase(java.util.Locale.ROOT);
        String current = props.getProperty("_channel.runtimeId", "");
        String id = props.getProperty("_channel.id", "");
        if (!normalized.isBlank() && normalized.equals(current) && id.matches("[a-f0-9]{32}")) return id;
        id = java.util.UUID.randomUUID().toString().replace("-", "").toLowerCase(java.util.Locale.ROOT);
        props.setProperty("_channel.runtimeId", normalized);
        props.setProperty("_channel.id", id);
        props.setProperty("_channel.ackedSequence", "0");
        persist();
        return id;
    }

    synchronized long acknowledgedSequence() {
        try { return Math.max(0L, Long.parseLong(props.getProperty("_channel.ackedSequence", "0"))); }
        catch (NumberFormatException ignored) { return 0; }
    }

    synchronized void acknowledgeSequence(long sequence) throws IOException {
        ensureOpen();
        if (sequence <= acknowledgedSequence()) return;
        props.setProperty("_channel.ackedSequence", Long.toString(sequence));
        persist();
    }

    synchronized State state(BridgeControlCommand command) {
        String prefix = prefix(command.commandId());
        String saved = props.getProperty(prefix + "digest", "");
        if (saved.isBlank()) return null;
        if (!saved.equals(command.digest())) throw new IllegalStateException("control command id reused with a different signed execution digest");
        String phase = props.getProperty(prefix + "phase", "");
        if ("done".equals(phase)) return new State(saved, phase, readResult(prefix));
        return new State(saved, phase, null);
    }

    synchronized void begin(BridgeControlCommand command) throws IOException {
        ensureOpen();
        String p = prefix(command.commandId());
        if (props.containsKey(p + "digest")) throw new IOException("command already admitted to durable journal");
        props.setProperty(p + "digest", command.digest());
        props.setProperty(p + "phase", "executing");
        props.setProperty(p + "runtime", command.runtimeId());
        props.setProperty(p + "sequence", Long.toString(command.deliverySequence()));
        props.setProperty(p + "channel", command.channelId());
        props.setProperty(p + "lease", command.leaseToken());
        props.setProperty(p + "updated", Long.toString(System.currentTimeMillis()));
        persist(); // durable write and directory fsync before invoking any side effect
    }

    synchronized void complete(BridgeControlCommand command, BridgeControlResult result) throws IOException {
        ensureOpen();
        String p = prefix(command.commandId());
        if (!command.digest().equals(props.getProperty(p + "digest")) || !"executing".equals(props.getProperty(p + "phase")))
            throw new IOException("cannot complete command without matching durable execution marker");
        props.setProperty(p + "phase", "done");
        props.setProperty(p + "status", result.status());
        props.setProperty(p + "result", BridgeControlCommand.encodeMap(result.result()));
        props.setProperty(p + "error", encode(result.error()));
        props.setProperty(p + "updated", Long.toString(System.currentTimeMillis()));
        persist();
    }

    /** Upgrade a 0.41.1 executed record after re-receiving the same verified signed delivery. */
    synchronized void bindLegacyReceipt(BridgeControlCommand command) throws IOException {
        ensureOpen();
        String p = prefix(command.commandId());
        if (!command.digest().equals(props.getProperty(p + "digest")))
            throw new IOException("receipt does not match the durable execution digest");
        String savedRuntime = props.getProperty(p + "runtime", "");
        if (!savedRuntime.isBlank()) {
            if (!savedRuntime.equals(command.runtimeId()) ||
                !Long.toString(command.deliverySequence()).equals(props.getProperty(p + "sequence")) ||
                !command.channelId().equals(props.getProperty(p + "channel")) ||
                !command.leaseToken().equals(props.getProperty(p + "lease")))
                throw new IOException("replayed delivery changes the durable lease identity");
            return;
        }
        props.setProperty(p + "runtime", command.runtimeId());
        props.setProperty(p + "sequence", Long.toString(command.deliverySequence()));
        props.setProperty(p + "channel", command.channelId());
        props.setProperty(p + "lease", command.leaseToken());
        persist();
    }

    synchronized List<Receipt> unacknowledged(String runtimeId, String channelId) throws IOException {
        ensureOpen();
        List<Receipt> receipts = new ArrayList<>();
        for (String key : props.stringPropertyNames()) {
            if (!key.endsWith(".phase") || !"done".equals(props.getProperty(key))) continue;
            String p = key.substring(0, key.length() - "phase".length());
            if (!runtimeId.equals(props.getProperty(p + "runtime")) || !channelId.equals(props.getProperty(p + "channel")) ||
                "true".equals(props.getProperty(p + "acked"))) continue;
            // Legacy entries have no lease metadata: they remain tombstones, never fabricated receipts.
            String token = props.getProperty(p + "lease", "");
            if (token.length() < 16) continue;
            long sequence;
            try { sequence = Long.parseLong(props.getProperty(p + "sequence", "")); }
            catch (NumberFormatException ex) { throw new IOException("invalid durable command sequence", ex); }
            if (sequence < 1) throw new IOException("invalid durable command sequence");
            receipts.add(new Receipt(p.substring(0, p.length() - 1), runtimeId, sequence, channelId, token, readResult(p)));
        }
        receipts.sort(java.util.Comparator.comparingLong(Receipt::sequence));
        return receipts;
    }

    synchronized void acknowledge(Receipt receipt) throws IOException {
        ensureOpen();
        String p = prefix(receipt.commandId());
        if (!"done".equals(props.getProperty(p + "phase")) || !receipt.runtimeId().equals(props.getProperty(p + "runtime")) ||
            !Long.toString(receipt.sequence()).equals(props.getProperty(p + "sequence")) ||
            !receipt.channelId().equals(props.getProperty(p + "channel")) || !receipt.leaseToken().equals(props.getProperty(p + "lease")))
            throw new IOException("control receipt no longer matches durable execution");
        props.setProperty(p + "acked", "true");
        if (receipt.sequence() > acknowledgedSequence())
            props.setProperty("_channel.ackedSequence", Long.toString(receipt.sequence()));
        persist();
    }

    private BridgeControlResult readResult(String p) {
        return new BridgeControlResult(props.getProperty(p + "status", "indeterminate"),
            BridgeControlCommand.decodePayload(props.getProperty(p + "result", "")),
            decode(props.getProperty(p + "error", "")));
    }

    private void ensureOpen() throws IOException {
        if (closed || !lock.isValid() || poisoned)
            throw new IOException("control journal is closed, corrupted or no longer writable");
    }
    private static String prefix(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{1,128}")) throw new IllegalArgumentException("invalid command id for durable journal");
        return id + ".";
    }
    private static String digest(Properties p) throws IOException {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (String key : new TreeSet<>(p.stringPropertyNames())) {
                if (CHECKSUM.equals(key)) continue;
                sha.update(key.getBytes(StandardCharsets.UTF_8)); sha.update((byte) 0);
                sha.update(p.getProperty(key).getBytes(StandardCharsets.UTF_8)); sha.update((byte) 10);
            }
            return HexFormat.of().formatHex(sha.digest());
        } catch (java.security.NoSuchAlgorithmException e) { throw new IOException("SHA-256 unavailable", e); }
    }
    private void persist() throws IOException {
        ensureOpen();
        props.setProperty(CHECKSUM, digest(props));
        Path tmp = path.resolveSibling(path.getFileName() + "." + java.util.UUID.randomUUID() + ".tmp");
        try {
            try (var out = Files.newOutputStream(tmp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                props.store(out, "NeverLauncher ServerBridge control journal");
            }
            setOwnerOnly(tmp);
            try (var ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) { ch.force(true); }
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            setOwnerOnly(path);
            // Sync the directory entry as well as file contents on POSIX hosts.
            if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
                try (var dir = FileChannel.open(path.getParent(), StandardOpenOption.READ)) { dir.force(true); }
            }
        } catch (IOException | RuntimeException e) {
            // A partially persisted marker cannot authorize more actions.
            // Operator must repair the journal/disk and restart the agent.
            poisoned = true;
            throw e;
        } finally { Files.deleteIfExists(tmp); }
    }
    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        try { lock.release(); } finally { lockChannel.close(); }
    }
    private static String encode(String s) { return Base64.getUrlEncoder().withoutPadding().encodeToString((s == null ? "" : s).getBytes(StandardCharsets.UTF_8)); }
    private static String decode(String s) {
        try { return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { throw new IllegalStateException("corrupt control journal error field", e); }
    }
    private static void setOwnerOnly(Path p) throws IOException {
        try { Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); }
        catch (UnsupportedOperationException ignored) { /* Windows ACL controlled by host configuration. */ }
    }
}
