package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Set;

/**
 * Small append-only durable journal for the ordered event stream. ACK records are
 * fsynced before pending events are discarded. The file is compacted atomically
 * after bounded progress so plugin reload/reconnect resumes from the last ACK.
 */
public final class BridgeEventJournal {
    private static final Set<PosixFilePermission> PRIVATE_PERMISSIONS = PosixFilePermissions.fromString("rw-------");
    private static final long COMPACT_SIZE = 2L * 1024L * 1024L;
    private static final int COMPACT_ACKS = 128;
    private static final int MAX_PENDING = 4096;

    private final Path path;
    private final String serverId;
    private final String runtimeId;
    private final NodeIdentity identity;
    private final TreeMap<Long, BridgeEventRecord> pending = new TreeMap<>();
    private long ackSequence;
    private long nextSequence = 1L;
    private int ackSinceCompaction;
    private String previousUncleanRuntimeId = "";

    public BridgeEventJournal(Path path, String serverId, String runtimeId, NodeIdentity identity) throws IOException {
        this.path = path.toAbsolutePath().normalize();
        this.serverId = serverId == null ? "" : serverId.trim();
        this.runtimeId = runtimeId == null ? "" : runtimeId.trim().toLowerCase();
        this.identity = identity;
        if (this.runtimeId.length() != 64) throw new IOException("event journal runtimeId is invalid");
        Path parent = this.path.getParent();
        if (parent != null) Files.createDirectories(parent);
        loadOrRotate();
        appendLine("O");
    }

    public synchronized String previousUncleanRuntimeId() { return previousUncleanRuntimeId; }
    public synchronized long ackSequence() { return ackSequence; }

    public synchronized BridgeEventRecord append(String type, Map<String, String> payload) throws IOException, GeneralSecurityException {
        if (pending.size() >= MAX_PENDING) throw new IOException("ServerBridge event journal pending limit reached");
        long sequence = nextSequence++;
        BridgeEventRecord event = BridgeEventRecord.signed(sequence, serverId, runtimeId, type, System.currentTimeMillis(), payload, identity);
        appendLine(encodeEvent(event));
        pending.put(sequence, event);
        return event;
    }

    public synchronized List<BridgeEventRecord> nextBatch(int max) {
        int limit = Math.max(1, Math.min(64, max));
        ArrayList<BridgeEventRecord> result = new ArrayList<>(limit);
        for (BridgeEventRecord event : pending.values()) {
            result.add(event);
            if (result.size() >= limit) break;
        }
        return List.copyOf(result);
    }

    public synchronized void acknowledge(long ack) throws IOException {
        if (ack <= ackSequence) return;
        long highest = pending.isEmpty() ? ackSequence : pending.lastKey();
        if (ack > highest) throw new IOException("backend ACK exceeds highest queued event sequence");
        appendLine("A\t" + ack);
        pending.headMap(ack, true).clear();
        ackSequence = ack;
        ackSinceCompaction++;
        if (ackSinceCompaction >= COMPACT_ACKS || Files.size(path) >= COMPACT_SIZE) compact();
    }

    public synchronized void markClean() throws IOException { appendLine("C"); }

    private void loadOrRotate() throws IOException {
        if (!Files.exists(path)) {
            initializeNew();
            return;
        }
        enforcePrivatePermissions(path);
        String existingRuntime = "";
        boolean clean = false;
        long loadedAck = 0L;
        TreeMap<Long, BridgeEventRecord> loaded = new TreeMap<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\\t", -1);
            switch (parts[0]) {
                case "R" -> {
                    existingRuntime = parts.length > 1 ? decode(parts[1]) : "";
                    clean = false;
                    loadedAck = 0L;
                    loaded.clear();
                }
                case "O" -> clean = false;
                case "C" -> clean = true;
                case "A" -> {
                    if (parts.length > 1) {
                        try { loadedAck = Math.max(loadedAck, Long.parseLong(parts[1])); } catch (NumberFormatException ignored) {}
                        loaded.headMap(loadedAck, true).clear();
                    }
                }
                case "E" -> {
                    BridgeEventRecord event = decodeEvent(parts);
                    if (event != null && event.sequence() > loadedAck) loaded.put(event.sequence(), event);
                    clean = false;
                }
                default -> { /* forward-compatible journal reader */ }
            }
        }
        if (!runtimeId.equalsIgnoreCase(existingRuntime)) {
            if (!existingRuntime.isBlank() && !clean) previousUncleanRuntimeId = existingRuntime;
            Path stale = path.resolveSibling(path.getFileName() + ".stale-" + System.currentTimeMillis());
            Files.move(path, stale, StandardCopyOption.REPLACE_EXISTING);
            initializeNew();
            return;
        }
        ackSequence = loadedAck;
        pending.putAll(loaded);
        nextSequence = Math.max(ackSequence + 1L, pending.isEmpty() ? 1L : pending.lastKey() + 1L);
    }

    private void initializeNew() throws IOException {
        Files.writeString(path, "R\t" + encode(runtimeId) + "\n", StandardCharsets.UTF_8,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        setPrivatePermissions(path);
        ackSequence = 0L;
        nextSequence = 1L;
        pending.clear();
    }

    private void compact() throws IOException {
        Path parent = path.getParent() == null ? Path.of(".").toAbsolutePath() : path.getParent();
        Path tmp = Files.createTempFile(parent, ".neverlauncher-events-", ".tmp");
        try {
            setPrivatePermissions(tmp);
            StringBuilder out = new StringBuilder();
            out.append("R\t").append(encode(runtimeId)).append('\n');
            if (ackSequence > 0) out.append("A\t").append(ackSequence).append('\n');
            out.append("O\n");
            for (BridgeEventRecord event : pending.values()) out.append(encodeEvent(event)).append('\n');
            Files.writeString(tmp, out.toString(), StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
            setPrivatePermissions(path);
            ackSinceCompaction = 0;
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private void appendLine(String line) throws IOException {
        byte[] data = (line + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        setPrivatePermissions(path);
    }

    private static String encodeEvent(BridgeEventRecord event) {
        return String.join("\t", "E", Long.toString(event.sequence()), Long.toString(event.occurredAtUnixMillis()),
            encode(event.eventId()), encode(event.type()), encode(BridgeEventRecord.payloadJson(new TreeMap<>(event.payload()))),
            event.payloadSha256(), encode(event.signature()));
    }

    private static BridgeEventRecord decodeEvent(String[] parts) {
        if (parts.length != 8) return null;
        try {
            long sequence = Long.parseLong(parts[1]);
            long occurred = Long.parseLong(parts[2]);
            String eventId = decode(parts[3]);
            String type = decode(parts[4]);
            Map<String, String> payload = parseFlatJsonObject(decode(parts[5]));
            String digest = parts[6];
            String signature = decode(parts[7]);
            String runtimeId = eventId.length() >= 64 ? eventId.substring(0, 64) : "";
            if (runtimeId.length() != 64) return null;
            return new BridgeEventRecord(sequence, eventId, runtimeId, type, occurred, payload, digest, signature);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static Map<String, String> parseFlatJsonObject(String raw) {
        TreeMap<String, String> out = new TreeMap<>();
        String value = raw == null ? "" : raw.trim();
        if (value.equals("{}")) return out;
        if (!value.startsWith("{") || !value.endsWith("}")) return out;
        int i = 1;
        while (i < value.length() - 1) {
            i = skipWhitespace(value, i);
            ParseString key = parseJsonString(value, i);
            if (key == null) return Map.of();
            i = skipWhitespace(value, key.next());
            if (i >= value.length() || value.charAt(i++) != ':') return Map.of();
            i = skipWhitespace(value, i);
            ParseString val = parseJsonString(value, i);
            if (val == null) return Map.of();
            out.put(key.value(), val.value());
            i = skipWhitespace(value, val.next());
            if (i < value.length() - 1 && value.charAt(i) == ',') i++;
        }
        return out;
    }

    private static int skipWhitespace(String s, int i) { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; return i; }
    private record ParseString(String value, int next) {}
    private static ParseString parseJsonString(String s, int start) {
        if (start >= s.length() || s.charAt(start) != '"') return null;
        StringBuilder out = new StringBuilder();
        for (int i = start + 1; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '"') return new ParseString(out.toString(), i + 1);
            if (ch == '\\') {
                if (++i >= s.length()) return null;
                char esc = s.charAt(i);
                switch (esc) {
                    case '"', '\\', '/' -> out.append(esc);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (i + 4 >= s.length()) return null;
                        try { out.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); } catch (NumberFormatException e) { return null; }
                        i += 4;
                    }
                    default -> { return null; }
                }
            } else out.append(ch);
        }
        return null;
    }

    private static String encode(String value) { return Base64.getUrlEncoder().withoutPadding().encodeToString((value == null ? "" : value).getBytes(StandardCharsets.UTF_8)); }
    private static String decode(String value) { return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8); }

    private static void enforcePrivatePermissions(Path path) throws IOException {
        try {
            for (PosixFilePermission permission : Files.getPosixFilePermissions(path)) {
                if (permission != PosixFilePermission.OWNER_READ && permission != PosixFilePermission.OWNER_WRITE) {
                    throw new IOException("event journal permissions must be 0600: " + path);
                }
            }
        } catch (UnsupportedOperationException ignored) {}
    }
    private static void setPrivatePermissions(Path path) throws IOException {
        try { Files.setPosixFilePermissions(path, PRIVATE_PERMISSIONS); } catch (UnsupportedOperationException ignored) {}
    }
}
