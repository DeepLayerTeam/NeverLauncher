package ru.neverlauncher.bridge.fabric;

import com.mojang.authlib.GameProfile;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerWorldEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.network.ClientConnection;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import net.minecraft.server.world.ServerWorld;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgeRuntimeProbe;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.BridgeControlCommand;
import ru.neverlauncher.bridge.common.BridgeControlResult;
import ru.neverlauncher.bridge.common.BridgeTickSampler;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;
import ru.neverlauncher.bridge.common.NodeIdentity;
import ru.neverlauncher.bridge.fabric.mixin.ServerLoginNetworkHandlerAccessor;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class NeverLauncherFabricBridge implements ModInitializer {
    private static final Logger LOGGER = LoggerFactory.getLogger("NeverLauncherFabricBridge");
    private static final String PLATFORM = "fabric";

    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean maintenanceMode = new AtomicBoolean(false);
    private final AtomicBoolean drainMode = new AtomicBoolean(false);
    private final ScheduledExecutorService heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(task -> daemonThread(task, "heartbeat"));
    private final ThreadPoolExecutor validationExecutor = new ThreadPoolExecutor(
        2,
        8,
        60L,
        TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(256),
        task -> daemonThread(task, "join"),
        new ThreadPoolExecutor.AbortPolicy()
    );

    private final BridgeTickSampler tickSampler = new BridgeTickSampler();
    private volatile long lastTelemetrySampleAt;
    private volatile RuntimeState state;
    private volatile boolean lastHeartbeatOK;
    private volatile Instant lastHeartbeatAt;

    public NeverLauncherFabricBridge() {
        validationExecutor.allowCoreThreadTimeOut(true);
    }

    @Override
    public void onInitialize() {
        try {
            state = loadState();
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher Fabric ServerBridge initialization failed", e);
        }

        ServerLoginConnectionEvents.QUERY_START.register(this::onLoginQueryStart);
        ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> onPlayerJoin(handler));
        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> onPlayerQuit(handler));
        ServerWorldEvents.LOAD.register((server, world) -> publishWorldEvent("world.load", world));
        ServerWorldEvents.UNLOAD.register((server, world) -> publishWorldEvent("world.unload", world));
        ServerLifecycleEvents.SERVER_STARTED.register(server -> {
            RuntimeState active = state;
            if (active != null) {
                active.api.startControlChannel(command -> executeControl(server, command));
                active.api.publishEvent("server.ready", Map.of("platform", PLATFORM));
            }
            scheduleHeartbeat(0);
        });
        ServerTickEvents.START_SERVER_TICK.register(server -> tickSampler.onTickStart());
        ServerTickEvents.END_SERVER_TICK.register(this::onServerTickEnd);
        ServerLifecycleEvents.SERVER_STOPPING.register(server -> close());

        RuntimeState current = state;
        current.api.publishEvent("server.startup", Map.of("platform", PLATFORM));
        LOGGER.info("NeverLauncher Fabric Server Bridge {} enabled; serverId={}; nodeKeyFingerprint={}; nodePublicKey={}; sha256={}; asyncLoginGate=true; clientModRequired=false",
            BridgeDefaults.VERSION,
            current.config.serverId,
            current.identity.fingerprint(),
            current.identity.publicKeyBase64Url(),
            shortHash(current.pluginSha256) + "; runtimeId=" + current.api.runtimeId());
    }

    private void onLoginQueryStart(ServerLoginNetworkHandler handler, MinecraftServer server,
                                   net.fabricmc.fabric.api.networking.v1.LoginPacketSender sender,
                                   net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking.LoginSynchronizer synchronizer) {
        if (stopping.get()) {
            handler.disconnect(Text.literal("NeverLauncher ServerBridge is stopping"));
            return;
        }
        if (maintenanceMode.get() || drainMode.get()) {
            handler.disconnect(Text.literal(maintenanceMode.get() ? "Server is in maintenance mode" : "Server is draining"));
            return;
        }

        LoginIdentity login = loginIdentity(handler);
        if (login.username.isBlank()) {
            handler.disconnect(Text.literal("NeverLauncher could not resolve the login profile"));
            return;
        }

        final CompletableFuture<JoinValidationResult> validation;
        try {
            validation = CompletableFuture.supplyAsync(
                () -> validateJoin(login.username, login.uuid, login.ip),
                validationExecutor
            );
        } catch (RejectedExecutionException e) {
            LOGGER.warn("NeverLauncher Fabric Bridge join validation queue saturated; failing closed username={}", login.username);
            handler.disconnect(Text.literal(new JoinValidationResult(false, "bridge_overloaded", "{}").userMessage()));
            return;
        }

        CompletableFuture<Void> gate = validation.handle((result, error) -> {
            if (error != null || result == null) {
                return new JoinValidationResult(false, "backend_unavailable", "{}");
            }
            return result;
        }).thenCompose(decision -> {
            RuntimeState active = state;
            if (active != null) active.api.publishEvent("player.login", Map.of(
                "username", login.username,
                "uuid", login.uuid,
                "allowed", Boolean.toString(decision.allowed),
                "reason", decision.reason == null ? "" : decision.reason
            ));
            if (decision.allowed) {
                LOGGER.info("neverlauncher.join.allowed username={} serverId={} platform=fabric", login.username, serverId());
                return CompletableFuture.completedFuture(null);
            }
            // Fabric's вход synchronizer может полный off logical сервер поток.
            // Отключаться на MinecraftServer's исполнитель и сохранять вход контроль blocked
            // до тот состояние переход имеет фактически был применённый.
            return server.submit(() -> {
                handler.disconnect(Text.literal(decision.userMessage()));
                LOGGER.info("neverlauncher.join.denied username={} reason={} platform=fabric", login.username, decision.reason);
            });
        });
        synchronizer.waitFor(gate);
    }

    private JoinValidationResult validateJoin(String username, String uuid, String ip) {
        RuntimeState current = state;
        if (current == null || stopping.get()) {
            return new JoinValidationResult(false, "bridge_runtime_unavailable", "{}");
        }
        return current.api.validateJoin(username, uuid, ip);
    }

    private RuntimeState loadState() throws Exception {
        Path configPath = FabricLoader.getInstance().getConfigDir()
            .resolve("neverlauncher-fabric-bridge")
            .resolve("config.yml")
            .toAbsolutePath()
            .normalize();
        BridgeConfig config = BridgeConfig.load(configPath, "fabric-main");
        String pluginSha256 = BridgeIntegrity.artifactSha256(getClass());
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) {
            throw new IllegalStateException("cannot measure running Fabric bridge JAR SHA-256");
        }
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        String loaderVersion = FabricLoader.getInstance().getModContainer("fabricloader")
            .map(container -> container.getMetadata().getVersion().getFriendlyString())
            .orElse(BridgeRuntimeProbe.packageVersion("net.fabricmc.loader.api.FabricLoader"));
        String minecraftVersion = FabricLoader.getInstance().getModContainer("minecraft")
            .map(container -> container.getMetadata().getVersion().getFriendlyString())
            .orElseGet(BridgeRuntimeProbe::minecraftVersion);
        BridgeRuntimeDescriptor descriptor = BridgeRuntimeDescriptor.of(
            minecraftVersion, PLATFORM, "Fabric Loader", loaderVersion,
            loaderVersion.isBlank() ? "Fabric" : "Fabric " + loaderVersion,
            java.util.List.of(
                "heartbeat.signed",
                "join.fabric-login-query-gate",
                "artifact.sha256",
                "artifact.loader-owned",
                "runtime.discovery",
                "runtime.ed25519-attestation",
                "telemetry.server-v1",
                "events.ordered-stream-v1",
                "control.secure-channel-v1",
                "loader.fabric"
            )
        );
        NeverLauncherApiClient api = new NeverLauncherApiClient(config, identity, PLATFORM, BridgeDefaults.VERSION, pluginSha256, descriptor);
        return new RuntimeState(config, identity, api, pluginSha256);
    }


    private void onServerTickEnd(MinecraftServer server) {
        tickSampler.onTickEnd();
        RuntimeState current = state;
        if (current == null || stopping.get()) return;
        long now = System.currentTimeMillis();
        long interval = Math.max(5L, current.config.telemetrySampleIntervalSeconds) * 1000L;
        if (now - lastTelemetrySampleAt < interval) return;
        lastTelemetrySampleAt = now;
        collectTelemetry(server, current);
    }

    private void collectTelemetry(MinecraftServer server, RuntimeState current) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(current.config.telemetrySamplingBudgetMs);
        BridgeTickSampler.TickMetrics tick = tickSampler.snapshot();
        int online = Math.max(0, server.getPlayerManager().getCurrentPlayerCount());
        int max = Math.max(online, server.getPlayerManager().getMaxPlayerCount());
        int worlds = 0;
        long chunks = 0L;
        long entities = 0L;
        boolean complete = true;
        boolean budgetExceeded = false;
        int entityProbe = 0;

        for (ServerWorld world : server.getWorlds()) {
            worlds++;
            if (worlds > 64 || System.nanoTime() > deadline) {
                complete = false;
                budgetExceeded = true;
                break;
            }
            chunks += Math.max(0, world.getChunkManager().getLoadedChunkCount());
            for (net.minecraft.entity.Entity ignored : world.iterateEntities()) {
                entities++;
                if ((++entityProbe & 255) == 0 && System.nanoTime() > deadline) {
                    complete = false;
                    budgetExceeded = true;
                    break;
                }
            }
            if (!complete) break;
        }

        java.util.ArrayList<String> metrics = new java.util.ArrayList<>();
        metrics.add("players");
        if (tick.tps() != null) metrics.add("tps");
        if (tick.mspt() != null) metrics.add("mspt");
        metrics.add("worlds");
        metrics.add("dimensions");
        if (complete) {
            metrics.add("chunks");
            metrics.add("entities");
        }
        current.api.recordPlatformTelemetry(BridgePlatformTelemetry.server(
            tick.tps(), tick.mspt(), online, max,
            worlds, worlds,
            complete ? chunks : null,
            complete ? entities : null,
            budgetExceeded,
            metrics
        ));
    }

    private void onPlayerJoin(net.minecraft.server.network.ServerPlayNetworkHandler handler) {
        RuntimeState current = state;
        if (current == null || handler == null || handler.getPlayer() == null) return;
        var profile = handler.getPlayer().getGameProfile();
        String username = profile == null || profile.getName() == null ? "" : profile.getName();
        String uuid = profile == null || profile.getId() == null ? "" : profile.getId().toString();
        current.api.publishEvent("player.join", Map.of("username", username, "uuid", uuid));
    }

    private void onPlayerQuit(net.minecraft.server.network.ServerPlayNetworkHandler handler) {
        RuntimeState current = state;
        if (current == null || handler == null || handler.getPlayer() == null) return;
        var profile = handler.getPlayer().getGameProfile();
        String username = profile == null || profile.getName() == null ? "" : profile.getName();
        String uuid = profile == null || profile.getId() == null ? "" : profile.getId().toString();
        current.api.publishEvent("player.quit", Map.of("username", username, "uuid", uuid));
    }

    private void publishWorldEvent(String type, ServerWorld world) {
        RuntimeState current = state;
        if (current == null || world == null) return;
        current.api.publishEvent(type, Map.of("world", world.getRegistryKey().getValue().toString()));
    }

    private void updateRoutingModes() {
        RuntimeState current = state;
        if (current != null) current.api.setRoutingModes(maintenanceMode.get(), drainMode.get());
        triggerHeartbeat();
    }

    private BridgeControlResult executeControl(MinecraftServer server, BridgeControlCommand command) throws Exception {
        Map<String,String> payload = command.payload();
        if ("server.maintenance".equals(command.type())) {
            boolean enabled = Boolean.parseBoolean(payload.getOrDefault("enabled", "false"));
            maintenanceMode.set(enabled);
            updateRoutingModes();
            return BridgeControlResult.ok(Map.of("enabled", Boolean.toString(enabled), "mode", "maintenance"));
        }
        if ("server.drain".equals(command.type())) {
            boolean enabled = Boolean.parseBoolean(payload.getOrDefault("enabled", "false"));
            drainMode.set(enabled);
            updateRoutingModes();
            return BridgeControlResult.ok(Map.of("enabled", Boolean.toString(enabled), "mode", "drain"));
        }
        if ("server.shutdown".equals(command.type())) {
            String reason = safeLine(payload.getOrDefault("reason", "Shutdown requested by NeverLauncher"), 512);
            Thread thread = new Thread(() -> {
                try { Thread.sleep(1500L); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                RuntimeState current = state;
                if (current != null) current.api.publishEvent("server.shutdown", Map.of("reason", reason, "source", "control-api"));
                server.stop(false);
            }, "neverlauncher-control-shutdown");
            thread.setDaemon(true);
            thread.start();
            return BridgeControlResult.ok(Map.of("scheduled", "true", "graceMillis", "1500"));
        }
        CompletableFuture<BridgeControlResult> future = new CompletableFuture<>();
        server.execute(() -> {
            try { future.complete(executeControlOnServerThread(server, command)); }
            catch (Throwable t) { future.completeExceptionally(t); }
        });
        try { return future.get(10, TimeUnit.SECONDS); }
        catch (java.util.concurrent.TimeoutException e) { return BridgeControlResult.indeterminate("platform_control_timeout"); }
    }

    private BridgeControlResult executeControlOnServerThread(MinecraftServer server, BridgeControlCommand command) {
        Map<String,String> payload = command.payload();
        switch (command.type()) {
            case "player.kick" -> {
                String username = safeUsername(payload.get("username"));
                var player = server.getPlayerManager().getPlayer(username);
                if (player == null) return BridgeControlResult.failed("player_not_online");
                player.networkHandler.disconnect(Text.literal(safeLine(payload.getOrDefault("reason", "Disconnected by server operator"), 512)));
                return BridgeControlResult.ok(Map.of("username", username));
            }
            case "message.broadcast" -> {
                String message = safeLine(payload.getOrDefault("message", ""), 1024);
                int recipients = server.getPlayerManager().getCurrentPlayerCount();
                for (var player : server.getPlayerManager().getPlayerList()) player.sendMessage(Text.literal(message), false);
                return BridgeControlResult.ok(Map.of("recipients", Integer.toString(recipients)));
            }
            case "whitelist.add", "whitelist.remove" -> {
                String username = safeUsername(payload.get("username"));
                boolean add = command.type().endsWith(".add");
                int code = executeMinecraftCommand(server, "whitelist " + (add ? "add " : "remove ") + username);
                return code >= 0 ? BridgeControlResult.ok(Map.of("username", username, "whitelisted", Boolean.toString(add))) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "whitelist.enable", "whitelist.disable" -> {
                boolean enabled = command.type().endsWith(".enable");
                int code = executeMinecraftCommand(server, "whitelist " + (enabled ? "on" : "off"));
                return code >= 0 ? BridgeControlResult.ok(Map.of("enabled", Boolean.toString(enabled))) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "ban.add", "ban.remove" -> {
                String username = safeUsername(payload.get("username"));
                boolean add = command.type().endsWith(".add");
                String reason = add ? safeLine(payload.getOrDefault("reason", "Banned by server operator"), 256) : "";
                int code = executeMinecraftCommand(server, (add ? "ban " : "pardon ") + username + (reason.isBlank() ? "" : " " + reason));
                return code >= 0 ? BridgeControlResult.ok(Map.of("username", username, "banned", Boolean.toString(add))) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "server.save" -> {
                int code = executeMinecraftCommand(server, "save-all flush");
                return code >= 0 ? BridgeControlResult.ok(Map.of("saved", "true")) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "server.console" -> {
                String raw = payload.getOrDefault("command", "").trim();
                if (raw.startsWith("/")) raw = raw.substring(1);
                RuntimeState current = state;
                if (current == null || !current.config.isConsoleCommandAllowed(raw)) return BridgeControlResult.failed("console_command_not_allowlisted");
                if (raw.isBlank() || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) return BridgeControlResult.failed("console_command_invalid");
                int code = executeMinecraftCommand(server, raw);
                return code >= 0 ? BridgeControlResult.ok(Map.of("accepted", "true", "resultCode", Integer.toString(code))) : BridgeControlResult.failed("platform_command_rejected");
            }
            default -> { return BridgeControlResult.unsupported("unsupported_control_type"); }
        }
    }

    private static int executeMinecraftCommand(MinecraftServer server, String command) {
        return server.getCommandManager().executeWithPrefix(server.getCommandSource(), command);
    }

    private static String safeUsername(String value) {
        String username = value == null ? "" : value.trim();
        if (!username.matches("[A-Za-z0-9_]{1,16}")) throw new IllegalArgumentException("invalid Minecraft username");
        return username;
    }

    private static String safeLine(String value, int max) {
        String out = value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').replace('\0', ' ').trim();
        return out.length() > max ? out.substring(0, max) : out;
    }

    private void scheduleHeartbeat(long delaySeconds) {
        if (stopping.get() || heartbeatExecutor.isShutdown()) return;
        heartbeatExecutor.schedule(() -> {
            if (stopping.get()) return;
            heartbeatOnce();
            RuntimeState current = state;
            scheduleHeartbeat(current == null ? 30 : current.config.heartbeatIntervalSeconds);
        }, Math.max(0, delaySeconds), TimeUnit.SECONDS);
    }

    private void heartbeatOnce() {
        RuntimeState current = state;
        if (current == null || stopping.get()) return;
        boolean ok = current.api.heartbeat(PLATFORM, BridgeDefaults.VERSION);
        boolean previous = lastHeartbeatOK;
        Instant previousAt = lastHeartbeatAt;
        lastHeartbeatOK = ok;
        lastHeartbeatAt = Instant.now();
        if (previousAt == null || previous != ok) {
            if (ok) {
                LOGGER.info("NeverLauncher Fabric Server Bridge heartbeat=true serverId={}", current.config.serverId);
            } else {
                LOGGER.warn("NeverLauncher Fabric Server Bridge heartbeat=false serverId={} reason=rejected_or_unavailable", current.config.serverId);
            }
        }
    }

    private void close() {
        if (!stopping.compareAndSet(false, true)) return;
        RuntimeState current = state;
        if (current != null) {
            current.api.publishEvent("server.shutdown", Map.of("platform", PLATFORM));
            current.api.flushEventsNow();
            current.api.closeEventStreamCleanly();
        }
        heartbeatExecutor.shutdownNow();
        validationExecutor.shutdownNow();
        try {
            boolean heartbeatStopped = heartbeatExecutor.awaitTermination(2, TimeUnit.SECONDS);
            boolean validationStopped = validationExecutor.awaitTermination(2, TimeUnit.SECONDS);
            if (!heartbeatStopped || !validationStopped) {
                LOGGER.warn("NeverLauncher Fabric ServerBridge workers did not terminate within shutdown window");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        state = null;
    }

    private String serverId() {
        RuntimeState current = state;
        return current == null ? "" : current.config.serverId;
    }

    private static LoginIdentity loginIdentity(ServerLoginNetworkHandler handler) {
        ServerLoginNetworkHandlerAccessor accessor = (ServerLoginNetworkHandlerAccessor) handler;
        GameProfile profile = accessor.neverlauncher$getProfile();
        String username = profile != null && profile.getName() != null ? profile.getName().trim() : "";
        if (username.isBlank()) {
            String profileName = accessor.neverlauncher$getProfileName();
            username = profileName == null ? "" : profileName.trim();
        }
        String uuid = profile != null && profile.getId() != null ? profile.getId().toString() : "";
        return new LoginIdentity(username, uuid, remoteIp(accessor.neverlauncher$getConnection()));
    }

    private static String remoteIp(ClientConnection connection) {
        if (connection == null) return "";
        SocketAddress address = connection.getAddress();
        if (address instanceof InetSocketAddress inet) {
            if (inet.getAddress() != null) return inet.getAddress().getHostAddress();
            return inet.getHostString();
        }
        return address == null ? "" : address.toString();
    }

    private Thread daemonThread(Runnable task, String role) {
        Thread thread = new Thread(task, "neverlauncher-fabric-bridge-" + role);
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler((t, error) -> {
            RuntimeState current = state;
            if (current != null) current.api.publishEvent("server.error", Map.of("component", role, "message", safeError(error)));
            LOGGER.error("NeverLauncher Fabric bridge {} worker failed", role, error);
        });
        return thread;
    }

    private static String safeError(Throwable error) {
        if (error == null) return "unknown";
        String value = error.getClass().getSimpleName() + ": " + String.valueOf(error.getMessage());
        value = value.replace('\r', ' ').replace('\n', ' ').trim();
        return value.length() > 512 ? value.substring(0, 512) : value;
    }

    private static String shortHash(String hash) {
        return BridgeIntegrity.isSha256(hash) ? hash.substring(0, 12) : "unavailable";
    }

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, NeverLauncherApiClient api, String pluginSha256) {}
    private record LoginIdentity(String username, String uuid, String ip) {}
}
