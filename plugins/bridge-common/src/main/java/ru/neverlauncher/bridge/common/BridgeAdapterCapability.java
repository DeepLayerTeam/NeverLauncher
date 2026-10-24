package ru.neverlauncher.bridge.common;

/**
 * Устойчивый словарь возможностей для поверхности универсального серверного адаптера.
 *
 * Возможности описывают фактические функции работающего адаптера. Имена
 * платформ — только метаданные обнаружения; безопасность и исполнение
 * должны проверять возможности, а не выводить поведение из бренда.
 */
public enum BridgeAdapterCapability {
    LOGIN_GATE("auth.login-gate"),
    PROXY_HANDOFF("routing.proxy-handoff"),
    PLAYER_LIFECYCLE("events.player-lifecycle"),
    WORLD_LIFECYCLE("events.world-lifecycle"),
    PROXY_LIFECYCLE("events.proxy-lifecycle"),
    TELEMETRY_PLAYERS("telemetry.players"),
    TELEMETRY_TPS("telemetry.tps"),
    TELEMETRY_MSPT("telemetry.mspt"),
    TELEMETRY_WORLDS("telemetry.worlds"),
    TELEMETRY_BOUNDED_WORLD_COUNTERS("telemetry.bounded-world-counters"),
    CONTROL_KICK("control.kick"),
    CONTROL_BROADCAST("control.broadcast"),
    CONTROL_WHITELIST("control.whitelist"),
    CONTROL_BAN("control.ban"),
    CONTROL_SAVE("control.save"),
    CONTROL_MAINTENANCE("control.maintenance"),
    CONTROL_DRAIN("control.drain"),
    CONTROL_SHUTDOWN("control.shutdown"),
    CONTROL_CONSOLE("control.console"),
    PAPER_API_FAMILY("api.paper-family"),
    REGION_SAFE_SCHEDULER("scheduler.region-safe"),
    NATIVE_SERVER_THREAD("scheduler.native-server-thread"),
    SIDECAR_RCON("sidecar.rcon"),
    SIDECAR_LOG_TAIL("sidecar.log-tail"),
    RUNTIME_ARTIFACT_MEASUREMENT("runtime.artifact-sha256");

    private final String wireName;

    BridgeAdapterCapability(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    public String runtimeCapability() {
        return "adapter." + wireName;
    }

    /** Map every remotely executable command to its explicitly advertised capability. */
    public static BridgeAdapterCapability forControl(String type) {
        if (type == null) return null;
        return switch (type) {
            case "player.kick" -> CONTROL_KICK;
            case "message.broadcast" -> CONTROL_BROADCAST;
            case "whitelist.add", "whitelist.remove", "whitelist.enable", "whitelist.disable" -> CONTROL_WHITELIST;
            case "ban.add", "ban.remove" -> CONTROL_BAN;
            case "server.save" -> CONTROL_SAVE;
            case "server.maintenance" -> CONTROL_MAINTENANCE;
            case "server.drain" -> CONTROL_DRAIN;
            case "server.shutdown" -> CONTROL_SHUTDOWN;
            case "server.console" -> CONTROL_CONSOLE;
            default -> null;
        };
    }
}
