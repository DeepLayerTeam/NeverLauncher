package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

public final class NeverLauncherApiClient {
    private static final String SIGNATURE_SCHEME = "NeverLauncher-ServerBridge-Node-v1";

    private final BridgeConfig config;
    private final NodeIdentity identity;
    private final HttpClient client;
    private final String serverType;
    private final String pluginVersion;
    private final String pluginSha256;

    public NeverLauncherApiClient(BridgeConfig config, NodeIdentity identity, String serverType, String pluginVersion, String pluginSha256) {
        this.config = config;
        this.identity = identity;
        this.serverType = normalized(serverType);
        this.pluginVersion = normalized(pluginVersion);
        this.pluginSha256 = normalized(pluginSha256).toLowerCase();
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.timeoutMs)).build();
    }

    public boolean heartbeat(String serverType, String pluginVersion) {
        String actualType = first(serverType, this.serverType);
        String actualVersion = first(pluginVersion, this.pluginVersion);
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) return false;
        String json = "{\"protocolVersion\":" + BridgeDefaults.PROTOCOL_VERSION +
            ",\"serverId\":" + quote(config.serverId) +
            ",\"serverType\":" + quote(actualType) +
            ",\"pluginVersion\":" + quote(actualVersion) +
            ",\"pluginSha256\":" + quote(pluginSha256) + "}";
        try {
            HttpRequest request = signedRequest("POST", URI.create(config.heartbeatUrl()), json);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    public JoinValidationResult validateJoin(String username, String uuid, String ip) {
        if (identity == null) {
            return new JoinValidationResult(false, "node_identity_missing", "{}");
        }
        if (config.requireIntegrity && (!BridgeIntegrity.isSha256(pluginSha256) || pluginVersion.isBlank() || serverType.isBlank())) {
            return new JoinValidationResult(false, "bridge_integrity_unavailable", "{}");
        }
        String body = "{" +
            "\"protocolVersion\":" + BridgeDefaults.PROTOCOL_VERSION + "," +
            "\"serverId\":" + quote(config.serverId) + "," +
            "\"username\":" + quote(username) + "," +
            "\"uuid\":" + quote(uuid) + "," +
            "\"ip\":" + quote(ip) + "," +
            "\"projectId\":" + quote(config.projectId) + "," +
            "\"profileId\":" + quote(config.profileId) + "," +
            "\"channel\":" + quote(config.channel) + "," +
            "\"pluginVersion\":" + quote(pluginVersion) + "," +
            "\"pluginSha256\":" + quote(pluginSha256) +
            "}";
        IOException lastIo = null;
        InterruptedException lastInterrupted = null;
        for (int attempt = 0; attempt <= Math.max(0, config.retries); attempt++) {
            try {
                // A retry is a new authenticated request with a fresh nonce. Reusing
                // a signed request would correctly be rejected as a replay.
                HttpRequest request = signedRequest("POST", URI.create(config.validateJoinUrl()), body);
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String raw = response.body() == null ? "" : response.body();
                boolean allowed = response.statusCode() >= 200 && response.statusCode() < 300 && raw.contains("\"allowed\":true");
                if (allowed) return new JoinValidationResult(true, "session_valid", raw);
                return new JoinValidationResult(false, extractReason(raw), raw);
            } catch (IOException e) {
                lastIo = e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                lastInterrupted = e;
                break;
            } catch (GeneralSecurityException e) {
                return new JoinValidationResult(false, "node_identity_signing_failed", "{}");
            }
        }
        String reason = lastInterrupted != null ? "backend_interrupted" : (lastIo != null ? "backend_unavailable" : "backend_denied");
        boolean failOpen = "open".equalsIgnoreCase(config.failMode) && !config.requireLauncherSession && !config.requireIntegrity;
        return new JoinValidationResult(failOpen, reason, "{}");
    }

    private HttpRequest signedRequest(String method, URI uri, String body) throws GeneralSecurityException {
        String timestamp = Long.toString(Instant.now().getEpochSecond());
        String nonce = identity.newNonce();
        String canonical = canonicalRequest(method, uri, body, timestamp, nonce);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(identity.sign(canonical));
        return HttpRequest.newBuilder(uri)
            .timeout(Duration.ofMillis(config.timeoutMs))
            .header("Content-Type", "application/json")
            .header("X-NeverLauncher-Node-Id", config.serverId)
            .header("X-NeverLauncher-Node-Key-Fingerprint", identity.fingerprint())
            .header("X-NeverLauncher-Node-Timestamp", timestamp)
            .header("X-NeverLauncher-Node-Nonce", nonce)
            .header("X-NeverLauncher-Node-Signature", signature)
            .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    }

    private String canonicalRequest(String method, URI uri, String body, String timestamp, String nonce) throws GeneralSecurityException {
        String target = uri.getRawPath();
        if (target == null || target.isEmpty()) target = "/";
        if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) target += "?" + uri.getRawQuery();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8));
        return String.join("\n",
            SIGNATURE_SCHEME,
            config.serverId.trim(),
            method.toUpperCase(),
            target,
            timestamp,
            nonce,
            HexFormat.of().formatHex(digest)
        );
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String extractReason(String raw) {
        String reason = extractJsonString(raw, "reason");
        if (!reason.isBlank()) return reason;
        String message = extractJsonString(raw, "message");
        return message.isBlank() ? "session_denied" : message;
    }

    private static String extractJsonString(String raw, String field) {
        String marker = "\"" + field + "\":";
        int idx = raw.indexOf(marker);
        if (idx < 0) return "";
        int start = raw.indexOf('"', idx + marker.length());
        int end = start >= 0 ? raw.indexOf('"', start + 1) : -1;
        if (start >= 0 && end > start) return raw.substring(start + 1, end);
        return "";
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }

    private static String first(String preferred, String fallback) {
        String value = normalized(preferred);
        return value.isBlank() ? normalized(fallback) : value;
    }
}
