package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class BridgeConfig {
    public final String backendUrl;
    public final String serverId;
    public final String serverToken;
    public final String projectId;
    public final String profileId;
    public final String channel;
    public final String failMode;
    public final boolean requireLauncherSession;
    public final int timeoutMs;
    public final int retries;

    private BridgeConfig(Map<String, String> values) {
        this.backendUrl = trimSlash(first(values, "backend.url", "NEVERLAUNCHER_BACKEND_URL", "http://127.0.0.1:8080"));
        this.serverId = first(values, "server.id", "NEVERLAUNCHER_SERVER_ID", "velocity-main");
        this.serverToken = first(values, "server.token", "NEVERLAUNCHER_SERVER_TOKEN", "");
        this.projectId = first(values, "profile.projectId", "NEVERLAUNCHER_PROJECT_ID", "default");
        this.profileId = first(values, "profile.profileId", "NEVERLAUNCHER_PROFILE_ID", "vanilla");
        this.channel = first(values, "profile.channel", "NEVERLAUNCHER_CHANNEL", "stable");
        this.failMode = first(values, "security.failMode", "NEVERLAUNCHER_FAIL_MODE", "closed");
        this.requireLauncherSession = Boolean.parseBoolean(first(values, "security.requireLauncherSession", "NEVERLAUNCHER_REQUIRE_SESSION", "true"));
        this.timeoutMs = parseInt(first(values, "backend.timeoutMs", "NEVERLAUNCHER_TIMEOUT_MS", "5000"), 5000);
        this.retries = parseInt(first(values, "backend.retries", "NEVERLAUNCHER_RETRIES", "2"), 2);
    }

    public static BridgeConfig load(Path configPath) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();
        if (Files.exists(configPath)) {
            String section = "";
            for (String raw : Files.readAllLines(configPath)) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (!raw.startsWith(" ") && !raw.startsWith("\t") && line.endsWith(":")) {
                    section = line.substring(0, line.length() - 1).trim();
                    continue;
                }
                int pos = line.indexOf(':');
                if (pos < 0) pos = line.indexOf('=');
                if (pos < 0) continue;
                String key = line.substring(0, pos).trim();
                String value = strip(line.substring(pos + 1).trim());
                values.put(section.isEmpty() ? key : section + "." + key, value);
            }
        }
        return new BridgeConfig(values);
    }

    public static BridgeConfig fromEnv() {
        return new BridgeConfig(Map.of());
    }

    public String validateJoinUrl() { return backendUrl + "/api/v1/server-bridge/validate-join"; }
    public String heartbeatUrl() { return backendUrl + "/api/v1/server-bridge/servers/" + serverId + "/heartbeat"; }
    public String statusUrl() { return backendUrl + "/api/v1/status"; }

    private static String first(Map<String, String> values, String key, String env, String fallback) {
        String value = values.get(key);
        if (value != null && !value.isBlank()) return value;
        value = System.getenv(env);
        if (value != null && !value.isBlank()) return value;
        return fallback;
    }

    private static int parseInt(String value, int fallback) {
        try { return Integer.parseInt(value); } catch (Exception ignored) { return fallback; }
    }

    private static String strip(String value) {
        if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) return value.substring(1, value.length() - 1);
        return value;
    }

    private static String trimSlash(String value) {
        while (value.endsWith("/")) value = value.substring(0, value.length() - 1);
        return value;
    }
}
