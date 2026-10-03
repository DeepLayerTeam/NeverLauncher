package ru.neverlauncher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public record BridgeControlCommand(
    String serverId,
    String commandId,
    String runtimeId,
    long runtimeEpoch,
    String type,
    Map<String, String> payload,
    String payloadSha256,
    int attempt,
    long issuedAtUnixMillis,
    long expiresAtUnixMillis,
    String signingPublicKey,
    String signature
) {
    public BridgeControlCommand {
        payload = payload == null ? Map.of() : Map.copyOf(payload);
    }

    public String canonical() {
        return String.join("\n",
            "NeverLauncher-ServerBridge-Control-v1",
            b64(serverId), b64(commandId), Long.toString(runtimeEpoch), runtimeId.toLowerCase(),
            b64(type), payloadSha256.toLowerCase(), Integer.toString(attempt),
            Long.toString(issuedAtUnixMillis), Long.toString(expiresAtUnixMillis));
    }

    /** Stable execution identity. Unlike the delivery signature it deliberately excludes lease attempt/timestamps,
     * so the same backend command can be re-delivered after a lost ACK without being treated as a different side effect. */
    public String executionDigest() {
        String stable = String.join("\n",
            "NeverLauncher-ServerBridge-Control-Execution-v1",
            b64(serverId), b64(commandId), Long.toString(runtimeEpoch), runtimeId.toLowerCase(),
            b64(type), payloadSha256.toLowerCase());
        try {
            byte[] raw = MessageDigest.getInstance("SHA-256").digest(stable.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String digest() { return executionDigest(); }

    public static Map<String, String> decodePayload(String encoded) {
        if (encoded == null || encoded.isBlank()) return Map.of();
        byte[] raw = Base64.getUrlDecoder().decode(encoded);
        if (raw.length > 4096) throw new IllegalArgumentException("control payload exceeds 4 KiB");
        return parseFlatJsonObject(new String(raw, StandardCharsets.UTF_8));
    }

    public static String encodeMap(Map<String, String> map) {
        StringBuilder out = new StringBuilder("{");
        int i = 0;
        for (var entry : new java.util.TreeMap<>(map == null ? Map.<String,String>of() : map).entrySet()) {
            if (i++ > 0) out.append(',');
            out.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(out.append('}').toString().getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, String> parseFlatJsonObject(String json) {
        String text = json == null ? "" : json.trim();
        if (text.equals("{}")) return Map.of();
        if (text.length() < 2 || text.charAt(0) != '{' || text.charAt(text.length()-1) != '}') throw new IllegalArgumentException("invalid control payload JSON");
        Map<String,String> out = new LinkedHashMap<>();
        int[] p = {1};
        while (true) {
            skipWs(text,p);
            if (p[0] >= text.length()-1) break;
            String key = readString(text,p); skipWs(text,p);
            if (p[0] >= text.length() || text.charAt(p[0]++) != ':') throw new IllegalArgumentException("invalid control payload JSON");
            skipWs(text,p); String value = readString(text,p);
            if (key.isEmpty() || key.length() > 64 || value.length() > 1024 || out.size() >= 16) throw new IllegalArgumentException("invalid control payload bounds");
            out.put(key,value); skipWs(text,p);
            if (p[0] < text.length()-1 && text.charAt(p[0]) == ',') { p[0]++; continue; }
            if (p[0] == text.length()-1) break;
            throw new IllegalArgumentException("invalid control payload JSON");
        }
        return Map.copyOf(out);
    }

    private static String readString(String text, int[] p) {
        if (p[0] >= text.length() || text.charAt(p[0]++) != '"') throw new IllegalArgumentException("JSON string required");
        StringBuilder out = new StringBuilder();
        while (p[0] < text.length()) {
            char c = text.charAt(p[0]++);
            if (c == '"') return out.toString();
            if (c == '\\') {
                if (p[0] >= text.length()) throw new IllegalArgumentException("invalid escape");
                char e = text.charAt(p[0]++);
                switch (e) {
                    case '"','\\','/' -> out.append(e);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (p[0] + 4 > text.length()) throw new IllegalArgumentException("invalid unicode escape");
                        try { out.append((char) Integer.parseInt(text.substring(p[0], p[0] + 4), 16)); }
                        catch (NumberFormatException ex) { throw new IllegalArgumentException("invalid unicode escape", ex); }
                        p[0] += 4;
                    }
                    default -> throw new IllegalArgumentException("unsupported escape");
                }
            } else { out.append(c); }
        }
        throw new IllegalArgumentException("unterminated string");
    }
    private static void skipWs(String text,int[] p){ while(p[0]<text.length() && Character.isWhitespace(text.charAt(p[0])))p[0]++; }
    private static String b64(String value){ return Base64.getUrlEncoder().withoutPadding().encodeToString((value==null?"":value.trim()).getBytes(StandardCharsets.UTF_8)); }
    private static String quote(String value){
        if(value==null)value=""; StringBuilder out=new StringBuilder(value.length()+2).append('"');
        for(int i=0;i<value.length();i++){ char c=value.charAt(i); switch(c){
            case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\"); case '\b' -> out.append("\\b");
            case '\f' -> out.append("\\f"); case '\n' -> out.append("\\n"); case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
            default -> { if(c<0x20) out.append(String.format("\\u%04x",(int)c)); else out.append(c); }
        }} return out.append('"').toString();
    }
}
