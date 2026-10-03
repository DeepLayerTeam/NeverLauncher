package ru.neverlauncher.bridge.bukkit;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerKickEvent;
import org.bukkit.event.world.WorldLoadEvent;
import org.bukkit.event.world.WorldUnloadEvent;
import org.bukkit.plugin.java.JavaPlugin;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;
import ru.neverlauncher.bridge.common.NodeIdentity;

import java.nio.file.Path;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Production Bukkit-family ServerBridge runtime shared by CraftBukkit, Spigot,
 * Paper, Purpur and Folia artifacts.
 *
 * No Bukkit scheduler is used for network I/O. Heartbeats run on a dedicated
 * daemon executor, which avoids main-thread stalls on classic servers and avoids
 * illegal global/region scheduler assumptions on Folia. Login validation runs in
 * AsyncPlayerPreLoginEvent and must complete before the server accepts the login.
 */
public abstract class BukkitFamilyBridgePlugin extends JavaPlugin implements Listener, CommandExecutor {
    private final BukkitFamilyPlatform expectedPlatform;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private volatile RuntimeState runtime;
    private volatile boolean lastHeartbeatOK;
    private volatile Instant lastHeartbeatAt;
    private ScheduledExecutorService networkExecutor;
    private volatile Object telemetryTask;
    private volatile Object foliaTelemetryTask;

    protected BukkitFamilyBridgePlugin(BukkitFamilyPlatform expectedPlatform) {
        this.expectedPlatform = expectedPlatform;
    }

    @Override
    public final void onEnable() {
        BukkitFamilyPlatform actual = BukkitFamilyPlatform.detect();
        if (actual != expectedPlatform) {
            getLogger().severe("NeverLauncher " + expectedPlatform.displayName() + " Bridge cannot run on detected platform " + actual.displayName() + ". Install neverlauncher-" + actual.id() + "-bridge instead.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        try {
            runtime = loadRuntime();
        } catch (Exception e) {
            getLogger().severe("NeverLauncher ServerBridge initialization failed: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("nlbridge") != null) getCommand("nlbridge").setExecutor(this);

        networkExecutor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "neverlauncher-bridge-io-" + expectedPlatform.id());
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((t, error) -> {
                RuntimeState state = runtime;
                if (state != null) state.api.publishEvent("server.error", Map.of("component", "io", "message", safeError(error)));
                getLogger().severe("NeverLauncher bridge I/O worker failed: " + error.getMessage());
            });
            return thread;
        });
        startTelemetrySampling();
        scheduleHeartbeat(0);

        RuntimeState state = runtime;
        state.api.publishEvent("server.startup", Map.of("platform", expectedPlatform.id()));
        state.api.publishEvent("server.ready", Map.of("platform", expectedPlatform.id()));
        getLogger().info("NeverLauncher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
            " enabled; serverId=" + state.config.serverId +
            "; nodeKeyFingerprint=" + state.identity.fingerprint() +
            "; sha256=" + shortHash(state.pluginSha256) +
            "; runtimeId=" + state.api.runtimeId() +
            "; foliaSafeIO=true");
    }

    @Override
    public final void onDisable() {
        stopping.set(true);
        RuntimeState state = runtime;
        if (state != null) {
            state.api.publishEvent("server.shutdown", Map.of("platform", expectedPlatform.id()));
            state.api.flushEventsNow();
            state.api.closeEventStreamCleanly();
        }
        stopTelemetrySampling();
        ScheduledExecutorService executor = networkExecutor;
        if (executor != null) {
            executor.shutdownNow();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    getLogger().warning("NeverLauncher bridge I/O worker did not terminate within shutdown window");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        runtime = null;
    }

    @EventHandler
    public final void onPreLogin(AsyncPlayerPreLoginEvent event) {
        RuntimeState state = runtime;
        if (state == null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, "NeverLauncher ServerBridge is not ready");
            return;
        }
        String ip = event.getAddress() == null ? "" : event.getAddress().getHostAddress();
        JoinValidationResult result = state.api.validateJoin(event.getName(), String.valueOf(event.getUniqueId()), ip);
        state.api.publishEvent("player.login", Map.of(
            "username", event.getName(),
            "uuid", String.valueOf(event.getUniqueId()),
            "allowed", Boolean.toString(result.allowed),
            "reason", result.reason == null ? "" : result.reason
        ));
        if (!result.allowed) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, result.userMessage());
            getLogger().info("neverlauncher.join.denied username=" + event.getName() + " reason=" + result.reason + " platform=" + expectedPlatform.id());
            return;
        }
        getLogger().info("neverlauncher.join.allowed username=" + event.getName() + " serverId=" + state.config.serverId + " platform=" + expectedPlatform.id());
    }

    @EventHandler
    public final void onPlayerJoin(PlayerJoinEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("player.join", Map.of("username", event.getPlayer().getName(), "uuid", String.valueOf(event.getPlayer().getUniqueId())));
    }

    @EventHandler
    public final void onPlayerQuit(PlayerQuitEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("player.quit", Map.of("username", event.getPlayer().getName(), "uuid", String.valueOf(event.getPlayer().getUniqueId())));
    }

    @EventHandler
    public final void onPlayerKick(PlayerKickEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("player.kick", Map.of("username", event.getPlayer().getName(), "uuid", String.valueOf(event.getPlayer().getUniqueId()), "reason", safe(String.valueOf(event.getReason()))));
    }

    @EventHandler
    public final void onWorldLoad(WorldLoadEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("world.load", Map.of("world", event.getWorld().getName(), "uuid", String.valueOf(event.getWorld().getUID())));
    }

    @EventHandler
    public final void onWorldUnload(WorldUnloadEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("world.unload", Map.of("world", event.getWorld().getName(), "uuid", String.valueOf(event.getWorld().getUID())));
    }

    @Override
    public final boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length == 0 ? "status" : args[0].toLowerCase(Locale.ROOT);
        RuntimeState state = runtime;
        if (state == null) {
            sender.sendMessage("NeverLauncher ServerBridge is not initialized");
            return true;
        }
        switch (sub) {
            case "status" -> {
                sender.sendMessage("NeverLauncher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
                    " serverId=" + state.config.serverId + " backend=" + state.config.backendUrl +
                    " heartbeat=" + heartbeatStatus());
                return true;
            }
            case "test" -> {
                if (!sender.hasPermission("neverlauncher.bridge.admin")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.admin");
                    return true;
                }
                triggerHeartbeat();
                sender.sendMessage("NeverLauncher heartbeat queued; last=" + heartbeatStatus());
                return true;
            }
            case "reload" -> {
                if (!sender.hasPermission("neverlauncher.bridge.reload")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.reload");
                    return true;
                }
                try {
                    RuntimeState previous = runtime;
                    RuntimeState next = loadRuntime();
                    runtime = next;
                    if (previous != null) previous.api.closeEventStreamCleanly();
                    next.api.publishEvent("server.ready", Map.of("platform", expectedPlatform.id(), "reason", "reload"));
                    triggerHeartbeat();
                    sender.sendMessage("NeverLauncher bridge configuration reloaded; serverId=" + next.config.serverId + " nodeKeyFingerprint=" + next.identity.fingerprint());
                } catch (Exception e) {
                    sender.sendMessage("NeverLauncher reload failed; previous runtime kept active: " + e.getMessage());
                }
                return true;
            }
            case "diagnostics" -> {
                if (!sender.hasPermission("neverlauncher.bridge.diagnostics")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.diagnostics");
                    return true;
                }
                sender.sendMessage("NeverLauncher diagnostics: platform=" + expectedPlatform.id() +
                    ", detected=" + BukkitFamilyPlatform.detect().id() +
                    ", failMode=" + state.config.failMode +
                    ", requireLauncherSession=" + state.config.requireLauncherSession +
                    ", requireIntegrity=" + state.config.requireIntegrity +
                    ", project=" + state.config.projectId + "/" + state.config.profileId + "/" + state.config.channel +
                    ", heartbeatIntervalSeconds=" + state.config.heartbeatIntervalSeconds +
                    ", runtimeId=" + state.api.runtimeId() +
                    ", heartbeat=" + heartbeatStatus());
                return true;
            }
            default -> {
                sender.sendMessage("Команды: /nlbridge status | test | reload | diagnostics");
                return true;
            }
        }
    }

    private RuntimeState loadRuntime() throws Exception {
        Path configPath = getDataFolder().toPath().resolve("config.yml");
        BridgeConfig config = BridgeConfig.load(configPath, expectedPlatform.id() + "-main");
        String pluginSha256 = BridgeIntegrity.artifactSha256(getClass());
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) {
            throw new IllegalStateException("cannot measure running plugin JAR SHA-256");
        }
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        NeverLauncherApiClient api = new NeverLauncherApiClient(config, identity, expectedPlatform.id(), BridgeDefaults.VERSION, pluginSha256, runtimeDescriptor());
        return new RuntimeState(config, identity, api, pluginSha256);
    }

    private BridgeRuntimeDescriptor runtimeDescriptor() {
        List<String> capabilities = new ArrayList<>(List.of(
            "heartbeat.signed",
            "join.async-prelogin-gate",
            "artifact.sha256",
            "runtime.discovery",
            "runtime.ed25519-attestation",
            "telemetry.server-v1",
                        "events.ordered-stream-v1",
            "plugin.bukkit-api"
        ));
        if (expectedPlatform == BukkitFamilyPlatform.FOLIA) capabilities.add("scheduler.folia-safe-io");
        if (expectedPlatform == BukkitFamilyPlatform.PAPER || expectedPlatform == BukkitFamilyPlatform.PURPUR || expectedPlatform == BukkitFamilyPlatform.FOLIA) {
            capabilities.add("server.paper-api-family");
        }
        String bukkitVersion = safe(Bukkit.getBukkitVersion());
        String minecraftVersion = bukkitVersion;
        int apiSuffix = minecraftVersion.indexOf("-R");
        if (apiSuffix > 0) minecraftVersion = minecraftVersion.substring(0, apiSuffix);
        String serverVersion = safe(Bukkit.getVersion());
        String brand = safe(Bukkit.getName());
        if (!serverVersion.isBlank()) brand = brand.isBlank() ? serverVersion : brand + " " + serverVersion;
        return BridgeRuntimeDescriptor.of(minecraftVersion, expectedPlatform.id(), expectedPlatform.displayName(), serverVersion, brand, capabilities);
    }


    private void startTelemetrySampling() {
        RuntimeState state = runtime;
        if (state == null || stopping.get()) return;
        long periodTicks = Math.max(100L, state.config.telemetrySampleIntervalSeconds * 20L);
        if (expectedPlatform != BukkitFamilyPlatform.FOLIA) {
            try {
                Object scheduler = Bukkit.class.getMethod("getScheduler").invoke(null);
                Method runTaskTimer = scheduler.getClass().getMethod(
                    "runTaskTimer", org.bukkit.plugin.Plugin.class, Runnable.class, long.class, long.class
                );
                telemetryTask = runTaskTimer.invoke(scheduler, this, (Runnable) this::collectTelemetry, 1L, periodTicks);
            } catch (ReflectiveOperationException e) {
                getLogger().warning("NeverLauncher telemetry: Bukkit scheduler unavailable; JVM telemetry will continue without platform counters: " + e.getMessage());
            }
            return;
        }
        // Folia does not permit a classic Bukkit scheduler task. Use the global
        // region scheduler reflectively so bridge-common keeps a Spigot API
        // compile surface while the dedicated Folia artifact remains region-safe.
        try {
            Method getter = Bukkit.class.getMethod("getGlobalRegionScheduler");
            Object scheduler = getter.invoke(null);
            Method run = null;
            for (Method candidate : scheduler.getClass().getMethods()) {
                if (candidate.getName().equals("runAtFixedRate") && candidate.getParameterCount() == 4) {
                    run = candidate;
                    break;
                }
            }
            if (run == null) throw new NoSuchMethodException("GlobalRegionScheduler.runAtFixedRate");
            Consumer<Object> task = ignored -> collectTelemetry();
            foliaTelemetryTask = run.invoke(scheduler, this, task, 1L, periodTicks);
        } catch (ReflectiveOperationException e) {
            getLogger().warning("NeverLauncher telemetry: Folia global scheduler unavailable; JVM telemetry will continue without platform counters: " + e.getMessage());
        }
    }

    private void stopTelemetrySampling() {
        Object task = telemetryTask;
        telemetryTask = null;
        if (task != null) {
            try { task.getClass().getMethod("cancel").invoke(task); } catch (ReflectiveOperationException | RuntimeException ignored) {}
        }
        Object folia = foliaTelemetryTask;
        foliaTelemetryTask = null;
        if (folia != null) {
            try { folia.getClass().getMethod("cancel").invoke(folia); } catch (ReflectiveOperationException | RuntimeException ignored) {}
        }
    }

    private void collectTelemetry() {
        RuntimeState state = runtime;
        if (state == null || stopping.get()) return;
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(state.config.telemetrySamplingBudgetMs);
        List<String> metrics = new ArrayList<>();
        int playersOnline = Bukkit.getOnlinePlayers().size();
        int playersMax = Math.max(playersOnline, Bukkit.getMaxPlayers());
        metrics.add("players");

        Double tps = reflectDoubleArrayFirst(Bukkit.class, "getTPS");
        if (tps != null) metrics.add("tps");
        Double mspt = reflectDouble(Bukkit.class, "getAverageTickTime");
        if (mspt == null) mspt = averageTickTimes();
        if (mspt != null) metrics.add("mspt");

        Integer worlds = null;
        Integer dimensions = null;
        Long chunks = null;
        Long entities = null;
        boolean budgetExceeded = false;

        try {
            List<org.bukkit.World> loaded = Bukkit.getWorlds();
            worlds = loaded.size();
            dimensions = loaded.size();
            metrics.add("worlds");
            metrics.add("dimensions");

            // Paper/Purpur expose constant-time world counters. Bukkit/Spigot
            // only expose APIs that materialize loaded-chunk/entity collections,
            // which can violate the telemetry sampling budget on large worlds.
            // Folia also requires region ownership for arbitrary world state, so
            // those platforms intentionally report these counters as unsupported.
            if ((expectedPlatform == BukkitFamilyPlatform.PAPER || expectedPlatform == BukkitFamilyPlatform.PURPUR) && loaded.size() <= 64) {
                long chunkTotal = 0L;
                long entityTotal = 0L;
                boolean complete = true;
                for (org.bukkit.World world : loaded) {
                    if (System.nanoTime() > deadline) {
                        complete = false;
                        budgetExceeded = true;
                        break;
                    }
                    Integer worldChunks = reflectInt(world, "getChunkCount");
                    Integer worldEntities = reflectInt(world, "getEntityCount");
                    if (worldChunks == null || worldEntities == null) {
                        complete = false;
                        break;
                    }
                    chunkTotal += worldChunks;
                    entityTotal += worldEntities;
                }
                if (complete) {
                    chunks = chunkTotal;
                    entities = entityTotal;
                    metrics.add("chunks");
                    metrics.add("entities");
                }
            } else if (loaded.size() > 64) {
                budgetExceeded = true;
            }
        } catch (RuntimeException e) {
            // Metrics are best-effort and never allowed to affect login/auth.
            budgetExceeded = true;
        }

        state.api.recordPlatformTelemetry(BridgePlatformTelemetry.server(
            tps, mspt, playersOnline, playersMax,
            worlds, dimensions, chunks, entities, budgetExceeded, metrics
        ));
    }

    private static Integer reflectInt(Object target, String method) {
        try {
            Object value = target.getClass().getMethod(method).invoke(target);
            if (value instanceof Number number) {
                long result = number.longValue();
                return result >= 0L && result <= Integer.MAX_VALUE ? (int) result : null;
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        return null;
    }

    private static Double reflectDouble(Class<?> type, String method) {
        try {
            Object value = type.getMethod(method).invoke(null);
            if (value instanceof Number number) {
                double result = number.doubleValue();
                return Double.isFinite(result) && result >= 0.0d ? result : null;
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        return null;
    }

    private static Double reflectDoubleArrayFirst(Class<?> type, String method) {
        try {
            Object value = type.getMethod(method).invoke(null);
            if (value instanceof double[] array && array.length > 0 && Double.isFinite(array[0])) {
                return Math.max(0.0d, array[0]);
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {}
        return null;
    }

    private static Double averageTickTimes() {
        try {
            Object value = Bukkit.class.getMethod("getTickTimes").invoke(null);
            if (!(value instanceof long[] ticks) || ticks.length == 0) return null;
            long total = 0L;
            int count = 0;
            for (long tick : ticks) {
                if (tick < 0L) continue;
                total += tick;
                count++;
            }
            return count == 0 ? null : (total / (double) count) / 1_000_000.0d;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return null;
        }
    }

    private static String safeError(Throwable error) {
        if (error == null) return "unknown";
        String value = error.getClass().getSimpleName() + ": " + String.valueOf(error.getMessage());
        value = value.replace('\r', ' ').replace('\n', ' ').trim();
        return value.length() > 512 ? value.substring(0, 512) : value;
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').trim();
    }

    private void scheduleHeartbeat(long delaySeconds) {
        ScheduledExecutorService executor = networkExecutor;
        if (executor == null || executor.isShutdown() || stopping.get()) return;
        executor.schedule(() -> {
            if (stopping.get()) return;
            RuntimeState state = runtime;
            if (state != null) {
                boolean ok = state.api.heartbeat(expectedPlatform.id(), BridgeDefaults.VERSION);
                recordHeartbeat(state, ok);
            }
            RuntimeState next = runtime;
            long interval = next == null ? 30 : next.config.heartbeatIntervalSeconds;
            scheduleHeartbeat(interval);
        }, Math.max(0, delaySeconds), TimeUnit.SECONDS);
    }

    private void triggerHeartbeat() {
        ScheduledExecutorService executor = networkExecutor;
        if (executor == null || executor.isShutdown() || stopping.get()) return;
        executor.execute(() -> {
            RuntimeState state = runtime;
            if (state == null) return;
            boolean ok = state.api.heartbeat(expectedPlatform.id(), BridgeDefaults.VERSION);
            recordHeartbeat(state, ok);
        });
    }

    private void recordHeartbeat(RuntimeState state, boolean ok) {
        boolean previous = lastHeartbeatOK;
        Instant previousAt = lastHeartbeatAt;
        lastHeartbeatOK = ok;
        lastHeartbeatAt = Instant.now();
        if (previousAt == null || previous != ok) {
            if (ok) {
                getLogger().info("NeverLauncher " + expectedPlatform.displayName() + " Bridge heartbeat=true serverId=" + state.config.serverId);
            } else {
                getLogger().warning("NeverLauncher " + expectedPlatform.displayName() + " Bridge heartbeat=false serverId=" + state.config.serverId + " reason=rejected_or_unavailable");
            }
        }
    }

    private String heartbeatStatus() {
        Instant at = lastHeartbeatAt;
        if (at == null) return "pending";
        return (lastHeartbeatOK ? "ok@" : "failed@") + at;
    }

    private static String shortHash(String hash) {
        return BridgeIntegrity.isSha256(hash) ? hash.substring(0, 12) : "unavailable";
    }

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, NeverLauncherApiClient api, String pluginSha256) {}
}
