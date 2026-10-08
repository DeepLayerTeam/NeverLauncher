package ru.neverlauncher.bridge.common;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/** One immutable Protocol-v3 Ed25519-signed ServerBridge event. */
public record BridgeEventRecord(
    long sequence,
    String eventId,
    String runtimeId,
    String type,
    long occurredAtUnixMillis,
    Map<String, String> payload,
    String payloadSha256,
    String securityProfile,
    String capabilityDigest,
    String nodeKeyFingerprint,
    String signature
) {
    public BridgeEventRecord {
        payload = payload == null ? Map.of() : Map.copyOf(payload);
        securityProfile = normalized(securityProfile);
        capabilityDigest = normalized(capabilityDigest).toLowerCase();
        nodeKeyFingerprint = normalized(nodeKeyFingerprint).toLowerCase();
    }

    public static BridgeEventRecord signed(long sequence, String serverId, String runtimeId, String type,
                                           long occurredAtUnixMillis, Map<String, String> payload, NodeIdentity identity)
        throws GeneralSecurityException {
        if (sequence < 1) throw new IllegalArgumentException("event sequence must be positive");
        String cleanType = normalized(type);
        if (cleanType.isEmpty() || cleanType.length() > 96 || cleanType.indexOf('\n') >= 0 || cleanType.indexOf('\r') >= 0) throw new IllegalArgumentException("invalid event type");
        String cleanRuntime = normalized(runtimeId).toLowerCase();
        if (cleanRuntime.length() != 64) throw new IllegalArgumentException("runtimeId must be sha256 hex");
        TreeMap<String, String> sorted = sanitizePayload(payload);
        String payloadJson = payloadJson(sorted);
        if (payloadJson.getBytes(StandardCharsets.UTF_8).length > 4096) throw new IllegalArgumentException("event payload exceeds 4096 bytes");
        String digest = sha256Hex(payloadJson);
        String eventId = cleanRuntime + "-" + sequence;
        String capabilityDigest = BridgeProtocolSecurity.expectedCapabilityDigest();
        String fingerprint = identity.fingerprint().toLowerCase();
        String canonical = BridgeProtocolSecurity.eventCanonical(serverId, eventId, cleanRuntime, fingerprint, capabilityDigest,
            sequence, cleanType, occurredAtUnixMillis, digest);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(identity.sign(canonical));
        return new BridgeEventRecord(sequence, eventId, cleanRuntime, cleanType, occurredAtUnixMillis, Map.copyOf(sorted), digest,
            BridgeProtocolSecurity.PROFILE, capabilityDigest, fingerprint, signature);
    }

    public String toJson() {
        return "{" +
            "\"sequence\":" + sequence +
            ",\"eventId\":" + quote(eventId) +
            ",\"runtimeId\":" + quote(runtimeId) +
            ",\"type\":" + quote(type) +
            ",\"occurredAtUnixMillis\":" + occurredAtUnixMillis +
            ",\"payload\":" + payloadJson(new TreeMap<>(payload)) +
            ",\"payloadSha256\":" + quote(payloadSha256) +
            ",\"securityProfile\":" + quote(securityProfile) +
            ",\"securityCapabilityDigest\":" + quote(capabilityDigest) +
            ",\"nodeKeyFingerprint\":" + quote(nodeKeyFingerprint) +
            ",\"signature\":" + quote(signature) +
            "}";
    }

    static String payloadJson(Map<String, String> payload) {
        StringBuilder out = new StringBuilder("{"); boolean first = true;
        for (Map.Entry<String, String> entry : payload.entrySet()) {
            if (!first) out.append(','); first = false;
            out.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        return out.append('}').toString();
    }

    private static TreeMap<String, String> sanitizePayload(Map<String, String> payload) {
        TreeMap<String, String> out = new TreeMap<>();
        if (payload == null) return out;
        if (payload.size() > 32) throw new IllegalArgumentException("event payload has too many keys");
        for (Map.Entry<String, String> entry : payload.entrySet()) {
            String key = normalized(entry.getKey()); String value = normalized(entry.getValue());
            if (key.isEmpty() || key.length() > 64 || key.indexOf('\n') >= 0 || key.indexOf('\r') >= 0 || key.indexOf('\0') >= 0) throw new IllegalArgumentException("invalid event payload key");
            if (value.length() > 1024 || value.indexOf('\0') >= 0) throw new IllegalArgumentException("event payload value too large");
            out.put(key, value);
        }
        return out;
    }

    private static String sha256Hex(String value) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    private static String quote(String value) {
        if (value == null) value = "";
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) { char ch = value.charAt(i); switch (ch) {
            case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\"); case '\n' -> out.append("\\n");
            case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
            default -> { if (ch < 0x20 || ch == '<' || ch == '>' || ch == '&' || ch == '\u2028' || ch == '\u2029') out.append(String.format("\\u%04x", (int) ch)); else out.append(ch); }
        }}
        return out.append('"').toString();
    }
    private static String normalized(String value) { return value == null ? "" : value.trim(); }
}
