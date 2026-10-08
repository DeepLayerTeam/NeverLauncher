package ru.neverlauncher.bridge.common;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Канонический рабочий возможность профили для Универсальный Сервер Адаптеры. */
public final class BridgeAdapterProfiles {
    private static final Set<BridgeAdapterCapability> SERVER_COMMON = EnumSet.of(
        BridgeAdapterCapability.LOGIN_GATE,
        BridgeAdapterCapability.PLAYER_LIFECYCLE,
        BridgeAdapterCapability.TELEMETRY_PLAYERS,
        BridgeAdapterCapability.TELEMETRY_TPS,
        BridgeAdapterCapability.TELEMETRY_MSPT,
        BridgeAdapterCapability.TELEMETRY_WORLDS,
        BridgeAdapterCapability.CONTROL_KICK,
        BridgeAdapterCapability.CONTROL_BROADCAST,
        BridgeAdapterCapability.CONTROL_WHITELIST,
        BridgeAdapterCapability.CONTROL_BAN,
        BridgeAdapterCapability.CONTROL_SAVE,
        BridgeAdapterCapability.CONTROL_MAINTENANCE,
        BridgeAdapterCapability.CONTROL_DRAIN,
        BridgeAdapterCapability.CONTROL_SHUTDOWN,
        BridgeAdapterCapability.CONTROL_CONSOLE,
        BridgeAdapterCapability.RUNTIME_ARTIFACT_MEASUREMENT
    );
    private static final Set<BridgeAdapterCapability> PROXY_COMMON = EnumSet.of(
        BridgeAdapterCapability.LOGIN_GATE,
        BridgeAdapterCapability.PROXY_HANDOFF,
        BridgeAdapterCapability.PLAYER_LIFECYCLE,
        BridgeAdapterCapability.PROXY_LIFECYCLE,
        BridgeAdapterCapability.TELEMETRY_PLAYERS,
        BridgeAdapterCapability.CONTROL_KICK,
        BridgeAdapterCapability.CONTROL_BROADCAST,
        BridgeAdapterCapability.CONTROL_MAINTENANCE,
        BridgeAdapterCapability.CONTROL_DRAIN,
        BridgeAdapterCapability.CONTROL_SHUTDOWN,
        BridgeAdapterCapability.CONTROL_CONSOLE,
        BridgeAdapterCapability.RUNTIME_ARTIFACT_MEASUREMENT
    );

    private static final Map<String, BridgeAdapterProfile> PROFILES = Map.ofEntries(
        Map.entry("velocity", profile("velocity", "proxy", "proxy", PROXY_COMMON)),
        Map.entry("bungeecord", profile("bungeecord", "proxy", "proxy", PROXY_COMMON)),
        Map.entry("waterfall", profile("waterfall", "proxy", "proxy", PROXY_COMMON)),
        Map.entry("bukkit", server("bukkit", "bukkit", false, false)),
        Map.entry("spigot", server("spigot", "bukkit", false, false)),
        Map.entry("paper", server("paper", "bukkit", true, false)),
        Map.entry("purpur", server("purpur", "bukkit", true, false)),
        Map.entry("folia", server("folia", "bukkit", false, true)),
        Map.entry("fabric", modloader("fabric", "fabric")),
        Map.entry("quilt", modloader("quilt", "quilt")),
        Map.entry("forge", modloader("forge", "modloader")),
        Map.entry("neoforge", modloader("neoforge", "modloader")),
        Map.entry("sponge", profile("sponge", "sponge", "backend", EnumSet.of(
            BridgeAdapterCapability.LOGIN_GATE,
            BridgeAdapterCapability.PLAYER_LIFECYCLE,
            BridgeAdapterCapability.TELEMETRY_PLAYERS,
            BridgeAdapterCapability.TELEMETRY_TPS,
            BridgeAdapterCapability.TELEMETRY_MSPT,
            BridgeAdapterCapability.TELEMETRY_WORLDS,
            BridgeAdapterCapability.CONTROL_KICK,
            BridgeAdapterCapability.CONTROL_BROADCAST,
            BridgeAdapterCapability.CONTROL_MAINTENANCE,
            BridgeAdapterCapability.CONTROL_DRAIN,
            BridgeAdapterCapability.CONTROL_SHUTDOWN,
            BridgeAdapterCapability.RUNTIME_ARTIFACT_MEASUREMENT
        ))),
        Map.entry("vanilla", profile("vanilla", "vanilla-sidecar", "backend", EnumSet.of(
            BridgeAdapterCapability.TELEMETRY_PLAYERS,
            BridgeAdapterCapability.PLAYER_LIFECYCLE,
            BridgeAdapterCapability.WORLD_LIFECYCLE,
            BridgeAdapterCapability.CONTROL_KICK,
            BridgeAdapterCapability.CONTROL_BROADCAST,
            BridgeAdapterCapability.CONTROL_WHITELIST,
            BridgeAdapterCapability.CONTROL_BAN,
            BridgeAdapterCapability.CONTROL_SAVE,
            BridgeAdapterCapability.CONTROL_MAINTENANCE,
            BridgeAdapterCapability.CONTROL_DRAIN,
            BridgeAdapterCapability.CONTROL_SHUTDOWN,
            BridgeAdapterCapability.CONTROL_CONSOLE,
            BridgeAdapterCapability.SIDECAR_RCON,
            BridgeAdapterCapability.SIDECAR_LOG_TAIL,
            BridgeAdapterCapability.RUNTIME_ARTIFACT_MEASUREMENT
        )))
    );

    private BridgeAdapterProfiles() {}

    public static BridgeAdapterProfile require(String platformId) {
        String id = normalize(platformId);
        BridgeAdapterProfile profile = PROFILES.get(id);
        if (profile == null) throw new IllegalArgumentException("unsupported ServerBridge adapter platform: " + id);
        return profile;
    }

    public static BridgeAdapterProfile find(String platformId) {
        return PROFILES.get(normalize(platformId));
    }

    public static Set<String> supportedPlatforms() {
        return PROFILES.keySet();
    }

    /**
     * Универсальный группа является намеренно отказ с блокировкой на гибридный ядра. Гибридный
     * продукт требовать их собственный evidence/certification матрица и должен не
     * inherit Bukkit/Forge сертификация всего лишь потому что их APIs resemble это.
     */
    public static void rejectUncertifiedHybrid(String platformId, String serverBrand) {
        String brand = normalize(serverBrand);
        if (brand.isEmpty()) return;
        for (String marker : new String[]{"mohist", "arclight", "magma", "catserver", "banner", "cardboard"}) {
            if (brand.contains(marker)) {
                throw new IllegalStateException(
                    "hybrid core '" + marker + "' is outside the Universal Server Adapter cohort; " +
                    "use a separately certified hybrid adapter/matrix instead of " + normalize(platformId)
                );
            }
        }
    }

    private static BridgeAdapterProfile server(String id, String family, boolean boundedWorldCounters, boolean regionSafe) {
        EnumSet<BridgeAdapterCapability> caps = EnumSet.copyOf(SERVER_COMMON);
        caps.add(BridgeAdapterCapability.WORLD_LIFECYCLE);
        caps.add(BridgeAdapterCapability.NATIVE_SERVER_THREAD);
        if (boundedWorldCounters) caps.add(BridgeAdapterCapability.TELEMETRY_BOUNDED_WORLD_COUNTERS);
        if (id.equals("paper") || id.equals("purpur") || id.equals("folia")) caps.add(BridgeAdapterCapability.PAPER_API_FAMILY);
        if (regionSafe) caps.add(BridgeAdapterCapability.REGION_SAFE_SCHEDULER);
        return profile(id, family, "backend", caps);
    }

    private static BridgeAdapterProfile modloader(String id, String family) {
        EnumSet<BridgeAdapterCapability> caps = EnumSet.copyOf(SERVER_COMMON);
        caps.add(BridgeAdapterCapability.WORLD_LIFECYCLE);
        caps.add(BridgeAdapterCapability.NATIVE_SERVER_THREAD);
        caps.add(BridgeAdapterCapability.TELEMETRY_BOUNDED_WORLD_COUNTERS);
        return profile(id, family, "backend", caps);
    }

    private static BridgeAdapterProfile profile(String id, String family, String role, Set<BridgeAdapterCapability> caps) {
        return new BridgeAdapterProfile(id, family, role, caps);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
