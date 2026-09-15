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

    public NeverLauncherApiClient(BridgeConfig config) {
        this.config = config;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.timeoutMs)).build();
    }

    public boolean heartbeat(String serverType, String pluginVersion) {
        String json = "{\"serverId\":" + quote(config.serverId) + ",\"serverType\":" + quote(serverType) + ",\"pluginVersion\":" + quote(pluginVersion) + "}";
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
        String body = "{" +
            "\"serverId\":" + quote(config.serverId) + "," +
            "\"username\":" + quote(username) + "," +
            "\"uuid\":" + quote(uuid) + "," +
            "\"ip\":" + quote(ip) + "," +
            "\"projectId\":" + quote(config.projectId) + "," +
            "\"profileId\":" + quote(config.profileId) + "," +
            "\"channel\":" + quote(config.channel) +
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
        boolean failOpen = "open".equalsIgnoreCase(config.failMode) && !config.requireLauncherSession;
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
}
