package ru.launcher.bridge.bukkit;

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
import ru.launcher.bridge.common.BridgeConfig;
import ru.launcher.bridge.common.BridgeAdapterCapability;
import ru.launcher.bridge.common.BridgeAdapterProfile;
import ru.launcher.bridge.common.BridgeAdapterProfiles;
import ru.launcher.bridge.common.BridgeControlCommand;
import ru.launcher.bridge.common.BridgeControlResult;
import ru.launcher.bridge.common.BridgeDefaults;
import ru.launcher.bridge.common.BridgeIntegrity;
import ru.launcher.bridge.common.BridgeRuntimeDescriptor;
import ru.launcher.bridge.common.BridgePlatformTelemetry;
import ru.launcher.bridge.common.JoinValidationResult;
import ru.launcher.bridge.common.LauncherApiClient;
import ru.launcher.bridge.common.NodeIdentity;

import java.nio.file.Path;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Производственная среда ServerBridge семейства Bukkit, общая
 * для артефактов CraftBukkit, Spigot, Paper, Purpur и Folia.
 *
 * Планировщик Bukkit не используется для сетевого ввода-вывода. Heartbeat выполняются
 * выделенным фоновым executor, предотвращая задержки главного потока старых серверов
 * и недопустимые предположения о глобальном или региональном планировщике Folia. Вход
 * проверяется в AsyncPlayerPreLoginEvent до допуска пользователя сервером.
 */
public abstract class BukkitFamilyBridgePlugin extends JavaPlugin implements Listener, CommandExecutor {
    private final BukkitFamilyPlatform expectedPlatform;
    private final BridgeAdapterProfile adapterProfile;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean maintenanceMode = new AtomicBoolean(false);
    private final AtomicBoolean drainMode = new AtomicBoolean(false);
    // ACK для player.kick должен связываться с реальным событием выхода игрока, а не с возвратом kickPlayer().
    // Карта принадлежит конкретному запущенному экземпляру плагина.
    private final ConcurrentHashMap<UUID, CompletableFuture<BridgeControlResult>> pendingKicks = new ConcurrentHashMap<>();
    private volatile RuntimeState runtime;
    private volatile boolean lastHeartbeatOK;
    private volatile Instant lastHeartbeatAt;
    private ScheduledExecutorService networkExecutor;
    private volatile Object telemetryTask;
    private volatile Object foliaTelemetryTask;

    protected BukkitFamilyBridgePlugin(BukkitFamilyPlatform expectedPlatform) {
        this.expectedPlatform = expectedPlatform;
        this.adapterProfile = BridgeAdapterProfiles.require(expectedPlatform.id());
    }

    @Override
    public final void onEnable() {
        stopping.set(false);
        BukkitFamilyPlatform actual = BukkitFamilyPlatform.detect();
        if (actual != expectedPlatform) {
            getLogger().severe("Launcher " + expectedPlatform.displayName() + " Bridge не может работать на обнаруженной платформе " + actual.displayName() + ". Install launcher-" + actual.id() + "-bridge instead.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        try {
            runtime = loadRuntime();
        } catch (Exception e) {
            getLogger().severe("Ошибка инициализации Launcher ServerBridge: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("nlbridge") != null) getCommand("nlbridge").setExecutor(this);

        networkExecutor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "launcher-bridge-io-" + expectedPlatform.id());
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((t, error) -> {
                RuntimeState state = runtime;
                if (state != null) state.api.publishEvent("server.error", Map.of("component", "io", "message", safeError(error)));
                getLogger().severe("Launcher bridge I/O worker failed: " + error.getMessage());
            });
            return thread;
        });
        startTelemetrySampling();
        scheduleHeartbeat(0);

        RuntimeState state = runtime;
        state.api.startControlChannel(this::executeControl);
        state.api.publishEvent("server.startup", Map.of("platform", expectedPlatform.id()));
        state.api.publishEvent("server.ready", Map.of("platform", expectedPlatform.id()));
        getLogger().info("Launcher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
            " enabled; serverId=" + state.config.serverId +
            "; nodeKeyFingerprint=" + state.identity.fingerprint() +
            "; sha256=" + shortHash(state.pluginSha256) +
            "; runtimeId=" + state.api.runtimeId() +
            "; foliaSafeIO=true");
    }

    @Override
    public final void onDisable() {
        stopping.set(true);
        // Не оставляйте команду в ожидании события, которое плагин уже не может выдать. Остановка не должна
        // превращаться в успешное завершение.
        pendingKicks.forEach((uuid, pending) -> pending.complete(BridgeControlResult.indeterminate("plugin_disabled_before_kick_confirmation")));
        pendingKicks.clear();
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
                    getLogger().warning("Launcher bridge I/O worker did not terminate within shutdown window");
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
        if (maintenanceMode.get() || drainMode.get()) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, maintenanceMode.get() ? "На сервере проводятся технические работы" : "Сервер завершает обслуживание подключений");
            return;
        }
        if (state == null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, "Мост Launcher ServerBridge ещё не готов");
            return;
        }
        String ip = event.getAddress() == null ? "" : event.getAddress().getHostAddress();
        JoinValidationResult result = state.api.validateJoin(event.getName(), String.valueOf(event.getUniqueId()), ip, Bukkit.getOnlineMode());
        state.api.publishEvent("player.login", Map.of(
            "username", event.getName(),
            "uuid", String.valueOf(event.getUniqueId()),
            "allowed", Boolean.toString(result.allowed),
            "reason", result.reason == null ? "" : result.reason
        ));
        if (!result.allowed) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, result.userMessage());
            getLogger().info("launcher.join.denied username=" + event.getName() + " reason=" + result.reason + " platform=" + expectedPlatform.id());
            return;
        }
        getLogger().info("launcher.join.allowed username=" + event.getName() + " serverId=" + state.config.serverId + " platform=" + expectedPlatform.id());
    }

    @EventHandler
    public final void onPlayerJoin(PlayerJoinEvent event) {
        RuntimeState state = runtime;
        if (state != null) state.api.publishEvent("player.join", Map.of("username", event.getPlayer().getName(), "uuid", String.valueOf(event.getPlayer().getUniqueId())));
    }

    @EventHandler
    public final void onPlayerQuit(PlayerQuitEvent event) {
        org.bukkit.entity.Player player = event.getPlayer();
        CompletableFuture<BridgeControlResult> pending = pendingKicks.remove(player.getUniqueId());
        if (pending != null) {
            // PlayerQuitEvent означает реально наблюдаемое отключение, в отличие от ACK планировщика или диспетчера. В
            // Folia событие может выполняться на потоке сущности.
            pending.complete(new BridgeControlResult("succeeded", Map.of(
                "verification", "player-quit-event", "username", player.getName(),
                "uuid", player.getUniqueId().toString(), "online", "false"), ""));
        }
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
            sender.sendMessage("Launcher ServerBridge не инициализирован");
            return true;
        }
        switch (sub) {
            case "status" -> {
                sender.sendMessage("Launcher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
                    " serverId=" + state.config.serverId + " backend=" + state.config.backendUrl +
                    " heartbeat=" + heartbeatStatus());
                return true;
            }
            case "test" -> {
                if (!sender.hasPermission("launcher.bridge.admin")) {
                    sender.sendMessage("Недостаточно прав: launcher.bridge.admin");
                    return true;
                }
                triggerHeartbeat();
                sender.sendMessage("Отправка сигнала активности Launcher поставлена в очередь; последний=" + heartbeatStatus());
                return true;
            }
            case "reload" -> {
                if (!sender.hasPermission("launcher.bridge.reload")) {
                    sender.sendMessage("Недостаточно прав: launcher.bridge.reload");
                    return true;
                }
                try {
                    RuntimeState previous = runtime;
                    RuntimeState next = loadRuntime();
                    runtime = next;
                    if (previous != null) previous.api.closeEventStreamCleanly();
                    // При /nlbridge reload сохраняйте фактическое состояние допуска; новый клиент API не должен сообщать
                    // ложный режим маршрутизации.
                    next.api.setRoutingModes(maintenanceMode.get(), drainMode.get());
                    next.api.startControlChannel(this::executeControl);
                    next.api.publishEvent("server.ready", Map.of("platform", expectedPlatform.id(), "reason", "reload"));
                    triggerHeartbeat();
                    sender.sendMessage("Конфигурация моста Launcher обновлена; serverId=" + next.config.serverId + " nodeKeyFingerprint=" + next.identity.fingerprint());
                } catch (Exception e) {
                    sender.sendMessage("Не удалось перезагрузить Launcher; предыдущая среда Runtime продолжает работать: " + e.getMessage());
                }
                return true;
            }
            case "diagnostics" -> {
                if (!sender.hasPermission("launcher.bridge.diagnostics")) {
                    sender.sendMessage("Недостаточно прав: launcher.bridge.diagnostics");
                    return true;
                }
                sender.sendMessage("Launcher diagnostics: platform=" + expectedPlatform.id() +
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
            throw new IllegalStateException("Не удалось вычислить SHA-256 работающего JAR плагина");
        }
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        BridgeRuntimeDescriptor descriptor = runtimeDescriptor();
        BridgeAdapterProfiles.rejectUncertifiedHybrid(expectedPlatform.id(), descriptor.serverBrand());
        LauncherApiClient api = new LauncherApiClient(config, identity, expectedPlatform.id(), BridgeDefaults.VERSION, pluginSha256, descriptor);
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
            "control.secure-channel-v1",
            "plugin.bukkit-api"
        ));
        if (adapterProfile.supports(BridgeAdapterCapability.REGION_SAFE_SCHEDULER)) capabilities.add("scheduler.folia-safe-io");
        if (adapterProfile.supports(BridgeAdapterCapability.PAPER_API_FAMILY)) {
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
        if (!adapterProfile.supports(BridgeAdapterCapability.REGION_SAFE_SCHEDULER)) {
            try {
                Object scheduler = Bukkit.class.getMethod("getScheduler").invoke(null);
                Method runTaskTimer = scheduler.getClass().getMethod(
                    "runTaskTimer", org.bukkit.plugin.Plugin.class, Runnable.class, long.class, long.class
                );
                telemetryTask = runTaskTimer.invoke(scheduler, this, (Runnable) this::collectTelemetry, 1L, periodTicks);
            } catch (ReflectiveOperationException e) {
                getLogger().warning("Launcher telemetry: Bukkit scheduler unavailable; JVM telemetry will continue without platform counters: " + e.getMessage());
            }
            return;
        }
        // Folia не разрешает стандартную задачу планировщика Bukkit. Используйте глобальный
        // региональный планировщик через рефлексию, чтобы bridge-common продолжал собираться
        // с API Spigot, а отдельный артефакт Folia соблюдал региональные правила.
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
            getLogger().warning("Launcher telemetry: Folia global scheduler unavailable; JVM telemetry will continue without platform counters: " + e.getMessage());
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

            // Paper/Purpur предоставляют счётчики мира за O(1). Bukkit/Spigot имеют
            // только API с формированием коллекций загруженных чанков и сущностей,
            // что на больших мирах превышает лимит сбора телеметрии. Folia также
            // требует владения регионом для произвольного состояния мира, поэтому
            // для этих платформ счётчики намеренно помечены неподдерживаемыми.
            if (adapterProfile.supports(BridgeAdapterCapability.TELEMETRY_BOUNDED_WORLD_COUNTERS) && loaded.size() <= 64) {
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
            // Метрики собираются по возможности и никогда не должны влиять на вход или аутентификацию.
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


    private BridgeControlResult executeControl(BridgeControlCommand command) throws Exception {
        String type = command.type();
        Map<String,String> payload = command.payload();
        if ("server.maintenance".equals(type)) {
            boolean enabled = Boolean.parseBoolean(payload.getOrDefault("enabled", "false"));
            maintenanceMode.set(enabled);
            updateRoutingModes();
            return maintenanceMode.get() == enabled
                ? BridgeControlResult.verified(Map.of("enabled", Boolean.toString(maintenanceMode.get()), "mode", "maintenance"))
                : BridgeControlResult.indeterminate("maintenance_state_not_observed");
        }
        if ("server.drain".equals(type)) {
            boolean enabled = Boolean.parseBoolean(payload.getOrDefault("enabled", "false"));
            drainMode.set(enabled);
            updateRoutingModes();
            return drainMode.get() == enabled
                ? BridgeControlResult.verified(Map.of("enabled", Boolean.toString(drainMode.get()), "mode", "drain"))
                : BridgeControlResult.indeterminate("drain_state_not_observed");
        }
        if ("server.shutdown".equals(type)) {
            ScheduledExecutorService executor = networkExecutor;
            if (executor == null || executor.isShutdown() || stopping.get())
                return BridgeControlResult.failed("shutdown_scheduler_unavailable");
            try {
                // Отложенная постановка в очередь не должна блокировать heartbeat и обработчик ввода-вывода событий.
                executor.schedule(() -> {
                    try { scheduleBukkitTask(Bukkit::shutdown); }
                    catch (RuntimeException e) { getLogger().severe("Minecraft shutdown scheduling failed: " + safeError(e)); }
                }, 1500L, TimeUnit.MILLISECONDS);
            } catch (java.util.concurrent.RejectedExecutionException e) {
                return BridgeControlResult.failed("shutdown_scheduler_rejected");
            }
            return BridgeControlResult.accepted(Map.of("scheduled", "true", "graceMillis", "1500"));
        }
        if ("player.kick".equals(type)) {
            return executePlayerKick(command);
        }
        if (adapterProfile.supports(BridgeAdapterCapability.REGION_SAFE_SCHEDULER) && "message.broadcast".equals(type)) {
            return executeFoliaBroadcast(command);
        }
        return callOnBukkitControlThread(() -> executeControlOnBukkitThread(command));
    }

    private void updateRoutingModes() {
        RuntimeState current = runtime;
        if (current != null) {
            current.api.setRoutingModes(maintenanceMode.get(), drainMode.get());
            ScheduledExecutorService executor = networkExecutor;
            if (executor != null && !executor.isShutdown()) triggerHeartbeat();
        }
    }

    private BridgeControlResult executeControlOnBukkitThread(BridgeControlCommand command) {
        Map<String,String> payload = command.payload();
        String type = command.type();
        switch (type) {
            case "message.broadcast" -> {
                String message = safeLine(payload.getOrDefault("message", ""), 1024);
                int recipients = Bukkit.getOnlinePlayers().size();
                Bukkit.broadcastMessage(message);
                return BridgeControlResult.ok(Map.of("recipients", Integer.toString(recipients)));
            }
            case "whitelist.add", "whitelist.remove" -> {
                String username = safeUsername(payload.get("username"));
                boolean add = type.endsWith(".add");
                boolean ok = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "whitelist " + (add ? "add " : "remove ") + username);
                if (!ok) return BridgeControlResult.failed("platform_command_rejected");
                // dispatchCommand(true) означает лишь приём команды диспетчером.
                boolean observed = Bukkit.getOfflinePlayer(username).isWhitelisted();
                return observed == add
                    ? BridgeControlResult.verified(Map.of("username", username, "whitelisted", Boolean.toString(observed)))
                    : BridgeControlResult.indeterminate("whitelist_postcondition_not_observed");
            }
            case "whitelist.enable", "whitelist.disable" -> {
                boolean enabled = type.endsWith(".enable");
                boolean ok = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "whitelist " + (enabled ? "on" : "off"));
                if (!ok) return BridgeControlResult.failed("platform_command_rejected");
                boolean observed = Bukkit.hasWhitelist();
                return observed == enabled
                    ? BridgeControlResult.verified(Map.of("enabled", Boolean.toString(observed)))
                    : BridgeControlResult.indeterminate("whitelist_mode_postcondition_not_observed");
            }
            case "ban.add", "ban.remove" -> {
                String username = safeUsername(payload.get("username"));
                String root = type.endsWith(".add") ? "ban " : "pardon ";
                String reason = type.endsWith(".add") ? safeLine(payload.getOrDefault("reason", "Заблокировано оператором сервера"), 256) : "";
                boolean ok = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), root + username + (reason.isBlank() ? "" : " " + reason));
                if (!ok) return BridgeControlResult.failed("platform_command_rejected");
                // Другие плагины могут переопределять диспетчер команд. Одного результата true недостаточно для
                // доказательства изменения блокировки.
                boolean observed = Bukkit.getOfflinePlayer(username).isBanned();
                boolean expected = type.endsWith(".add");
                return observed == expected
                    ? BridgeControlResult.verified(Map.of("username", username, "banned", Boolean.toString(observed)))
                    : BridgeControlResult.indeterminate("ban_postcondition_not_observed");
            }
            case "server.save" -> {
                boolean ok = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "save-all flush");
                return ok ? BridgeControlResult.ok(Map.of("saved", "true")) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "server.console" -> {
                String raw = payload.getOrDefault("command", "").trim();
                if (raw.startsWith("/")) raw = raw.substring(1);
                if (!runtime.config.isConsoleCommandAllowed(raw)) return BridgeControlResult.failed("console_command_not_allowlisted");
                if (raw.isBlank() || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) return BridgeControlResult.failed("console_command_invalid");
                boolean ok = Bukkit.dispatchCommand(Bukkit.getConsoleSender(), raw);
                return ok ? BridgeControlResult.ok(Map.of("accepted", "true")) : BridgeControlResult.failed("platform_command_rejected");
            }
            default -> { return BridgeControlResult.unsupported("unsupported_control_type"); }
        }
    }

    private BridgeControlResult executePlayerKick(BridgeControlCommand command) throws Exception {
        String username = safeUsername(command.payload().get("username"));
        String reason = safeLine(command.payload().getOrDefault("reason", "Отключено оператором сервера"), 512);
        String correlation = command.payload().getOrDefault("sessionCorrelationId", "");
        CompletableFuture<BridgeControlResult> confirmation = new CompletableFuture<>();
        // Весь доступ к платформе передаётся соответствующему планировщику сервера. Ожидает удалённый обработчик
        // управления, но никогда игровой поток Bukkit или Folia.
        scheduleBukkitTask(() -> {
            if (confirmation.isDone() || stopping.get()) return;
            try {
                org.bukkit.entity.Player player = Bukkit.getPlayerExact(username);
                if (player == null) {
                    confirmation.complete(BridgeControlResult.failed("player_not_online"));
                    return;
                }
                UUID id = player.getUniqueId();
                RuntimeState live = runtime;
                if (!correlation.isBlank() && (live == null || !live.api.matchesPlayerSession(username, correlation))) {
                    confirmation.complete(BridgeControlResult.failed("player_session_changed"));
                    return;
                }
                CompletableFuture<BridgeControlResult> previous = pendingKicks.putIfAbsent(id, confirmation);
                if (previous != null) {
                    confirmation.complete(BridgeControlResult.failed("player_kick_already_in_progress"));
                    return;
                }
                // При тайм-ауте или ошибке удаляйте только данного ожидающего, не удаляя новый обработчик, который уже мог
                // быть зарегистрирован для того же игрока.
                confirmation.whenComplete((result, error) -> pendingKicks.remove(id, confirmation));
                Runnable kick = () -> {
                    if (confirmation.isDone() || stopping.get()) return;
                    RuntimeState active = runtime;
                    if (!correlation.isBlank() && (active == null ||
                        !active.api.matchesPlayerSession(username, correlation) ||
                        Bukkit.getPlayerExact(username) != player)) {
                        confirmation.complete(BridgeControlResult.failed("player_session_changed"));
                        return;
                    }
                    try { player.kickPlayer(reason); }
                    catch (Throwable error) {
                        // Игрок мог уже выйти; не заменяйте подтверждённый результат PlayerQuitEvent исключением.
                        confirmation.complete(BridgeControlResult.indeterminate("player_kick_invocation_failed"));
                        getLogger().warning("Launcher player kick invocation: " + safeError(error));
                    }
                };
                if (adapterProfile.supports(BridgeAdapterCapability.REGION_SAFE_SCHEDULER)) {
                    boolean scheduled = scheduleFoliaEntityTask(player, kick,
                        () -> confirmation.complete(BridgeControlResult.indeterminate("player_retired_before_control")));
                    if (!scheduled) confirmation.complete(BridgeControlResult.failed("player_scheduler_rejected_control"));
                } else {
                    kick.run();
                }
            } catch (Throwable error) {
                confirmation.complete(BridgeControlResult.indeterminate("player_kick_scheduler_failed"));
                getLogger().warning("Launcher player kick scheduling: " + safeError(error));
            }
        });
        try {
            return confirmation.get(10L, TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            confirmation.complete(BridgeControlResult.indeterminate("player_quit_not_observed"));
            return confirmation.getNow(BridgeControlResult.indeterminate("player_quit_not_observed"));
        }
    }

    private BridgeControlResult executeFoliaBroadcast(BridgeControlCommand command) throws Exception {
        CompletableFuture<BridgeControlResult> future = new CompletableFuture<>();
        String message = safeLine(command.payload().getOrDefault("message", ""), 1024);
        scheduleBukkitTask(() -> {
            if (future.isDone() || stopping.get()) return;
            try {
                java.util.List<org.bukkit.entity.Player> players = new java.util.ArrayList<>(Bukkit.getOnlinePlayers());
                if (players.isEmpty()) { future.complete(BridgeControlResult.ok(Map.of("recipients", "0"))); return; }
                java.util.concurrent.atomic.AtomicInteger remaining = new java.util.concurrent.atomic.AtomicInteger(players.size());
                java.util.concurrent.atomic.AtomicInteger delivered = new java.util.concurrent.atomic.AtomicInteger();
                java.util.concurrent.atomic.AtomicInteger failed = new java.util.concurrent.atomic.AtomicInteger();
                Runnable finish = () -> {
                    if (remaining.decrementAndGet() == 0) {
                        // Частичная рассылка имеет неизвестные видимые эффекты. Нельзя представлять её как успешную полную
                        // доставку.
                        future.complete(failed.get() == 0
                            ? BridgeControlResult.ok(Map.of("recipients", Integer.toString(delivered.get())))
                            : BridgeControlResult.indeterminate("broadcast_partial_delivery"));
                    }
                };
                for (org.bukkit.entity.Player player : players) {
                    java.util.concurrent.atomic.AtomicBoolean settled = new java.util.concurrent.atomic.AtomicBoolean();
                    Runnable rejected = () -> {
                        // Планировщик Folia может вернуть false и одновременно состязаться с уже завершённым обратным вызовом;
                        // учитывайте каждого получателя один раз.
                        if (settled.compareAndSet(false, true)) {
                            failed.incrementAndGet();
                            finish.run();
                        }
                    };
                    Runnable task = () -> {
                        if (future.isDone() || stopping.get()) { rejected.run(); return; }
                        try { player.sendMessage(message); delivered.incrementAndGet(); }
                        catch (Throwable error) { failed.incrementAndGet(); }
                        finally { if (settled.compareAndSet(false, true)) finish.run(); }
                    };
                    try {
                        boolean scheduled = scheduleFoliaEntityTask(player, task, rejected);
                        if (!scheduled) rejected.run();
                    } catch (RuntimeException error) {
                        rejected.run();
                    }
                }
            } catch (Throwable error) {
                future.complete(BridgeControlResult.indeterminate("broadcast_scheduler_failed"));
            }
        });
        return awaitControlResult(future);
    }

    private boolean scheduleFoliaEntityTask(org.bukkit.entity.Player player, Runnable task, Runnable retired) {
        try {
            Object scheduler = player.getClass().getMethod("getScheduler").invoke(player);
            Method execute = scheduler.getClass().getMethod("execute", org.bukkit.plugin.Plugin.class, Runnable.class, Runnable.class, long.class);
            Object accepted = execute.invoke(scheduler, this, task, retired, 0L);
            return !(accepted instanceof Boolean flag) || flag;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Планировщик сущностей Folia недоступен", e);
        }
    }

    private static BridgeControlResult awaitControlResult(CompletableFuture<BridgeControlResult> future) throws Exception {
        try { return future.get(10, TimeUnit.SECONDS); }
        catch (java.util.concurrent.TimeoutException e) { return BridgeControlResult.indeterminate("platform_control_timeout"); }
    }

    private BridgeControlResult callOnBukkitControlThread(java.util.concurrent.Callable<BridgeControlResult> task) throws Exception {
        CompletableFuture<BridgeControlResult> future = new CompletableFuture<>();
        scheduleBukkitTask(() -> {
            try { future.complete(task.call()); }
            catch (Throwable t) { future.completeExceptionally(t); }
        });
        try { return future.get(10, TimeUnit.SECONDS); }
        catch (java.util.concurrent.TimeoutException e) { return BridgeControlResult.indeterminate("platform_control_timeout"); }
    }

    private void scheduleBukkitTask(Runnable task) {
        if (adapterProfile.supports(BridgeAdapterCapability.REGION_SAFE_SCHEDULER)) {
            try {
                Object scheduler = Bukkit.class.getMethod("getGlobalRegionScheduler").invoke(null);
                Method execute = scheduler.getClass().getMethod("execute", org.bukkit.plugin.Plugin.class, Runnable.class);
                execute.invoke(scheduler, this, task);
                return;
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Глобальный планировщик Folia недоступен", e);
            }
        }
        try {
            Object scheduler = Bukkit.class.getMethod("getScheduler").invoke(null);
            Method runTask = scheduler.getClass().getMethod("runTask", org.bukkit.plugin.Plugin.class, Runnable.class);
            runTask.invoke(scheduler, this, task);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Планировщик Bukkit недоступен", e);
        }
    }

    private static String safeUsername(String value) {
        String username = value == null ? "" : value.trim();
        if (!username.matches("[A-Za-z0-9_]{1,16}")) throw new IllegalArgumentException("Некорректное имя игрока Minecraft");
        return username;
    }

    private static String safeLine(String value, int max) {
        String out = value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').replace('\0', ' ').trim();
        return out.length() > max ? out.substring(0, max) : out;
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
                getLogger().info("Launcher " + expectedPlatform.displayName() + " Bridge heartbeat=true serverId=" + state.config.serverId);
            } else {
                getLogger().warning("Launcher " + expectedPlatform.displayName() + " Bridge heartbeat=false serverId=" + state.config.serverId + " reason=rejected_or_unavailable");
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

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, LauncherApiClient api, String pluginSha256) {}
}
