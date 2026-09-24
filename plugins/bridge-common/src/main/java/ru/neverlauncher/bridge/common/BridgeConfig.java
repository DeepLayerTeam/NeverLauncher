package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class BridgeConfig {
    public final String backendUrl;
    public final String serverId;
    public final Path identityFile;
    public final String projectId;
    public final String profileId;
    public final String channel;
    public final String failMode;
    public final boolean requireLauncherSession;
    public final boolean requireIntegrity;
    public final int timeoutMs;
    public final int retries;
    public final int heartbeatIntervalSeconds;

    private BridgeConfig(Map<String, String> values, Path configPath, String defaultServerId) {
        this.backendUrl = trimSlash(first(values, "backend.url", "NEVERLAUNCHER_BACKEND_URL", "http://127.0.0.1:8080"));
        this.serverId = first(values, "server.id", "NEVERLAUNCHER_SERVER_ID", defaultServerId);
        String identity = first(values, "identity.file", "NEVERLAUNCHER_NODE_IDENTITY_FILE", "node-identity.properties");
        Path configuredIdentity = Path.of(identity);
        if (!configuredIdentity.isAbsolute() && configPath != null && configPath.toAbsolutePath().getParent() != null) {
            configuredIdentity = configPath.toAbsolutePath().getParent().resolve(configuredIdentity);
        }
        this.identityFile = configuredIdentity.normalize();
        this.projectId = first(values, "profile.projectId", "NEVERLAUNCHER_PROJECT_ID", "default");
        this.profileId = first(values, "profile.profileId", "NEVERLAUNCHER_PROFILE_ID", "vanilla");
        this.channel = first(values, "profile.channel", "NEVERLAUNCHER_CHANNEL", "stable");
        this.failMode = first(values, "security.failMode", "NEVERLAUNCHER_FAIL_MODE", "closed");
        this.requireLauncherSession = Boolean.parseBoolean(first(values, "security.requireLauncherSession", "NEVERLAUNCHER_REQUIRE_SESSION", "true"));
        this.requireIntegrity = Boolean.parseBoolean(first(values, "security.requireIntegrity", "NEVERLAUNCHER_REQUIRE_BRIDGE_INTEGRITY", "true"));
        this.timeoutMs = parseInt(first(values, "backend.timeoutMs", "NEVERLAUNCHER_TIMEOUT_MS", "5000"), 5000);
        this.retries = boundedInt(first(values, "backend.retries", "NEVERLAUNCHER_RETRIES", "2"), 2, 0, 5);
        this.heartbeatIntervalSeconds = boundedInt(first(values, "backend.heartbeatIntervalSeconds", "NEVERLAUNCHER_HEARTBEAT_INTERVAL_SECONDS", "30"), 30, 10, 300);
    }

    public static BridgeConfig load(Path configPath) throws IOException {
        return load(configPath, "velocity-main");
    }

    public static BridgeConfig load(Path configPath, String defaultServerId) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();
        ensureZeroPatchConfig(configPath, normalizedDefaultServerId(defaultServerId));
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
        return new BridgeConfig(values, configPath, normalizedDefaultServerId(defaultServerId));
    }

    public static BridgeConfig fromEnv() {
        return fromEnv("velocity-main");
    }

    public static BridgeConfig fromEnv(String defaultServerId) {
        return new BridgeConfig(Map.of(), null, normalizedDefaultServerId(defaultServerId));
    }

    public String validateJoinUrl() { return backendUrl + "/api/v1/server-bridge/validate-join"; }
    public String handoffUrl() { return backendUrl + "/api/v1/server-bridge/handoff"; }
    public String heartbeatUrl() { return backendUrl + "/api/v1/server-bridge/servers/" + serverId + "/heartbeat"; }
    public String statusUrl() { return backendUrl + "/api/v1/status"; }

    private static void ensureZeroPatchConfig(Path configPath, String defaultServerId) {
        if (configPath == null || Files.exists(configPath)) return;
        try {
            Path absolute = configPath.toAbsolutePath().normalize();
            Path parent = absolute.getParent();
            if (parent != null) Files.createDirectories(parent);
            // Deliberately write comments only. Runtime values continue to come from
            // environment variables/defaults, so installing the JAR/mod never patches
            // Paper/Velocity/Bungee/Fabric/Forge configuration and never freezes env.
            String template = "# NeverLauncher ServerBridge " + BridgeDefaults.VERSION + " zero-patch bootstrap\n" +
                "# No Minecraft/proxy configuration is modified by this plugin.\n" +
                "# Defaults: backend=http://127.0.0.1:8080 server.id=" + defaultServerId + "\n" +
                "# Override with NEVERLAUNCHER_BACKEND_URL / NEVERLAUNCHER_SERVER_ID and related env vars,\n" +
                "# or add explicit keys here when file-based configuration is preferred.\n";
            Files.writeString(absolute, template, java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE);
        } catch (IOException | SecurityException ignored) {
            // Read-only plugin/mod directories are valid zero-patch deployments;
            // environment/default configuration remains authoritative.
        }
    }

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

    private static int boundedInt(String value, int fallback, int min, int max) {
        int parsed = parseInt(value, fallback);
        return Math.max(min, Math.min(max, parsed));
    }

    private static String normalizedDefaultServerId(String value) {
        if (value == null || value.isBlank()) return "server-main";
        return value.trim();
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
