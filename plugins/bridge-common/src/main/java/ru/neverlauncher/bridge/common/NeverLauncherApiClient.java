package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class NeverLauncherApiClient {
    private final BridgeConfig config;
    private final HttpClient client;
    private final String serverType;
    private final String pluginVersion;
    private final String pluginSha256;

    public NeverLauncherApiClient(BridgeConfig config) {
        this(config, "", "", "");
    }

    public NeverLauncherApiClient(BridgeConfig config, String serverType, String pluginVersion, String pluginSha256) {
        this.config = config;
        this.serverType = normalized(serverType);
        this.pluginVersion = normalized(pluginVersion);
        this.pluginSha256 = normalized(pluginSha256).toLowerCase();
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.timeoutMs)).build();
    }

    public boolean heartbeat(String serverType, String pluginVersion) {
        String actualType = first(serverType, this.serverType);
        String actualVersion = first(pluginVersion, this.pluginVersion);
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) return false;
        String json = "{\"serverId\":" + quote(config.serverId) +
            ",\"serverType\":" + quote(actualType) +
            ",\"pluginVersion\":" + quote(actualVersion) +
            ",\"pluginSha256\":" + quote(pluginSha256) + "}";
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(config.heartbeatUrl()))
                .timeout(Duration.ofMillis(config.timeoutMs))
                .header("Content-Type", "application/json")
                .header("X-NeverLauncher-Server-Token", config.serverToken)
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    public JoinValidationResult validateJoin(String username, String uuid, String ip) {
        if (config.serverToken == null || config.serverToken.isBlank()) {
            return new JoinValidationResult(!config.requireLauncherSession && "open".equals(config.failMode), "server_token_missing", "{}");
        }
        if (config.requireIntegrity && (!BridgeIntegrity.isSha256(pluginSha256) || pluginVersion.isBlank() || serverType.isBlank())) {
            return new JoinValidationResult(false, "bridge_integrity_unavailable", "{}");
        }
        String body = "{" +
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
                HttpRequest request = HttpRequest.newBuilder(URI.create(config.validateJoinUrl()))
                    .timeout(Duration.ofMillis(config.timeoutMs))
                    .header("Content-Type", "application/json")
                    .header("X-NeverLauncher-Server-Token", config.serverToken)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
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
            }
        }
        String reason = lastInterrupted != null ? "backend_interrupted" : (lastIo != null ? "backend_unavailable" : "backend_denied");
        boolean failOpen = "open".equalsIgnoreCase(config.failMode) && !config.requireLauncherSession && !config.requireIntegrity;
        return new JoinValidationResult(failOpen, reason, "{}");
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String extractReason(String raw) {
        int idx = raw.indexOf("\"reason\":");
        if (idx < 0) return "session_denied";
        int start = raw.indexOf('"', idx + 9);
        int end = start >= 0 ? raw.indexOf('"', start + 1) : -1;
        if (start >= 0 && end > start) return raw.substring(start + 1, end);
        return "session_denied";
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }

    private static String first(String preferred, String fallback) {
        String value = normalized(preferred);
        return value.isBlank() ? normalized(fallback) : value;
    }
}
