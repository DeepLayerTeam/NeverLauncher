package ru.neverlauncher.bridge.neoforge;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.configuration.ServerConfigurationPacketListener;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.ModList;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.server.ServerStartedEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.level.LevelEvent;
import net.neoforged.neoforge.event.tick.ServerTickEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.server.ServerLifecycleHooks;
import org.slf4j.Logger;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.BridgeControlCommand;
import ru.neverlauncher.bridge.common.BridgeControlResult;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgeRuntimeProbe;
import ru.neverlauncher.bridge.common.BridgeTickSampler;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.modloader.ModLoaderBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@Mod(NeverLauncherNeoForgeBridge.MOD_ID)
public final class NeverLauncherNeoForgeBridge {
    public static final String MOD_ID = "neverlauncher_serverbridge";
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final ConfigurationTask.Type JOIN_VALIDATION_TASK =
        new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(MOD_ID, "join_validation"));

    private final ModLoaderBridgeRuntime runtime;
    private final BridgeTickSampler tickSampler = new BridgeTickSampler();
    private long lastTelemetrySampleAt;

    public NeverLauncherNeoForgeBridge(IEventBus modEventBus, ModContainer modContainer) {
        Path configPath = FMLPaths.CONFIGDIR.get()
            .resolve("neverlauncher-neoforge-bridge")
            .resolve("config.yml");
        this.runtime = new ModLoaderBridgeRuntime(
            "neoforge", "NeoForge", configPath, NeverLauncherNeoForgeBridge.class, NeverLauncherNeoForgeBridge::loadedArtifactPath, LOGGER,
            () -> {
                String loaderVersion = BridgeRuntimeProbe.nestedStaticString("net.neoforged.fml.loading.FMLLoader", "versionInfo", "neoForgeVersion");
                if (loaderVersion.isBlank()) loaderVersion = BridgeRuntimeProbe.packageVersion("net.neoforged.fml.loading.FMLLoader");
                String minecraftVersion = BridgeRuntimeProbe.nestedStaticString("net.neoforged.fml.loading.FMLLoader", "versionInfo", "mcVersion");
                if (minecraftVersion.isBlank()) minecraftVersion = BridgeRuntimeProbe.minecraftVersion();
                return BridgeRuntimeDescriptor.of(
                    minecraftVersion, "neoforge", "NeoForge", loaderVersion,
                    loaderVersion.isBlank() ? "NeoForge" : "NeoForge " + loaderVersion,
                    java.util.List.of(
                        "heartbeat.signed",
                        "join.configuration-task-gate",
                        "artifact.sha256",
                        "artifact.loader-owned",
                        "runtime.discovery",
                        "runtime.ed25519-attestation",
                        "telemetry.server-v1",
                        "events.ordered-stream-v1",
                        "control.secure-channel-v1",
                        "loader.neoforge"
                    )
                );
            }
        );
        modEventBus.addListener(this::onRegisterConfigurationTasks);
        NeoForge.EVENT_BUS.register(this);
    }

    @SubscribeEvent
    public void onServerStarted(ServerStartedEvent event) {
        try {
            runtime.start();
            runtime.startControlChannel(command -> executeControl(event.getServer(), command));
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher NeoForge ServerBridge failed to start", e);
        }
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        runtime.close();
    }

    @SubscribeEvent
    public void onPlayerLoggedIn(PlayerEvent.PlayerLoggedInEvent event) {
        if (event.getEntity() == null) return;
        var profile = event.getEntity().getGameProfile();
        runtime.publishEvent("player.join", Map.of(
            "username", profile == null || profile.getName() == null ? "" : profile.getName(),
            "uuid", profile == null || profile.getId() == null ? "" : profile.getId().toString()
        ));
    }

    @SubscribeEvent
    public void onPlayerLoggedOut(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() == null) return;
        var profile = event.getEntity().getGameProfile();
        runtime.publishEvent("player.quit", Map.of(
            "username", profile == null || profile.getName() == null ? "" : profile.getName(),
            "uuid", profile == null || profile.getId() == null ? "" : profile.getId().toString()
        ));
    }

    @SubscribeEvent
    public void onLevelLoad(LevelEvent.Load event) {
        runtime.publishEvent("world.load", Map.of("world", String.valueOf(event.getLevel())));
    }

    @SubscribeEvent
    public void onLevelUnload(LevelEvent.Unload event) {
        runtime.publishEvent("world.unload", Map.of("world", String.valueOf(event.getLevel())));
    }

    @SubscribeEvent
    public void onServerTickPre(ServerTickEvent.Pre event) {
        tickSampler.onTickStart();
    }

    @SubscribeEvent
    public void onServerTickPost(ServerTickEvent.Post event) {
        tickSampler.onTickEnd();
        long now = System.currentTimeMillis();
        if (now - lastTelemetrySampleAt < runtime.telemetrySampleIntervalSeconds() * 1000L) return;
        lastTelemetrySampleAt = now;
        collectTelemetry(event.getServer(), now);
    }

    private void collectTelemetry(net.minecraft.server.MinecraftServer server, long sampledAt) {
        BridgeTickSampler.TickMetrics tick = tickSampler.snapshot();
        long deadline = System.nanoTime() + runtime.telemetrySamplingBudgetMs() * 1_000_000L;
        int worlds = 0;
        long chunks = 0L;
        long entities = 0L;
        boolean budgetExceeded = false;

        for (ServerLevel level : server.getAllLevels()) {
            if (++worlds > 64) {
                budgetExceeded = true;
                break;
            }
            chunks += Math.max(0, level.getChunkSource().getLoadedChunksCount());
            int checked = 0;
            for (var ignored : level.getAllEntities()) {
                entities++;
                if ((++checked & 255) == 0 && System.nanoTime() >= deadline) {
                    budgetExceeded = true;
                    break;
                }
            }
            if (budgetExceeded || System.nanoTime() >= deadline) {
                budgetExceeded = true;
                break;
            }
        }
        java.util.ArrayList<String> metrics = new java.util.ArrayList<>();
        if (tick.tps() != null) metrics.add("tps");
        if (tick.mspt() != null) metrics.add("mspt");
        metrics.add("players");
        metrics.add("worlds");
        metrics.add("dimensions");
        if (!budgetExceeded) {
            metrics.add("chunks");
            metrics.add("entities");
        }
        runtime.recordPlatformTelemetry(BridgePlatformTelemetry.server(
            tick.tps(), tick.mspt(), server.getPlayerCount(), server.getMaxPlayers(),
            worlds, worlds, budgetExceeded ? null : chunks, budgetExceeded ? null : entities,
            budgetExceeded, metrics
        ));
    }

    private void onRegisterConfigurationTasks(RegisterConfigurationTasksEvent event) {
        ServerConfigurationPacketListener listener = event.getListener();
        if (!(listener instanceof ServerCommonPacketListenerImpl serverListener)) {
            listener.disconnect(Component.literal("NeverLauncher could not resolve the configuration listener"));
            return;
        }

        GameProfile profile = serverListener.getOwner();
        String username = profile == null || profile.getName() == null ? "" : profile.getName().trim();
        String uuid = profile == null || profile.getId() == null ? "" : profile.getId().toString();
        event.register(new JoinValidationTask(listener, serverListener.getConnection(), username, uuid));
    }

    private final class JoinValidationTask implements ConfigurationTask {
        private final ServerConfigurationPacketListener listener;
        private final Connection connection;
        private final String username;
        private final String uuid;

        private JoinValidationTask(
            ServerConfigurationPacketListener listener,
            Connection connection,
            String username,
            String uuid
        ) {
            this.listener = listener;
            this.connection = connection;
            this.username = username;
            this.uuid = uuid;
        }

        @Override
        public void start(Consumer<Packet<?>> sender) {
            if (username.isBlank()) {
                listener.disconnect(Component.literal("NeverLauncher could not resolve the login profile"));
                return;
            }

            runtime.validateJoinAsync(username, uuid, remoteIp(connection))
                .handle((decision, error) -> error == null && decision != null
                    ? decision
                    : new JoinValidationResult(false, "backend_unavailable", "{}"))
                .thenAccept(this::completeOnServerThread);
        }

        @Override
        public Type type() {
            return JOIN_VALIDATION_TASK;
        }

        private void completeOnServerThread(JoinValidationResult decision) {
            var server = ServerLifecycleHooks.getCurrentServer();
            if (server == null) {
                listener.disconnect(Component.literal("NeverLauncher server is not available"));
                return;
            }

            server.execute(() -> {
                if (!connection.isConnected()) {
                    return;
                }
                runtime.publishEvent("player.login", Map.of(
                    "username", username,
                    "uuid", uuid,
                    "allowed", Boolean.toString(decision.allowed),
                    "reason", decision.reason == null ? "" : decision.reason
                ));
                if (decision.allowed) {
                    LOGGER.info(
                        "neverlauncher.join.allowed username={} serverId={} platform=neoforge",
                        username,
                        runtime.serverId()
                    );
                    listener.finishCurrentTask(JOIN_VALIDATION_TASK);
                    return;
                }

                listener.disconnect(Component.literal(decision.userMessage()));
                LOGGER.info(
                    "neverlauncher.join.denied username={} reason={} platform=neoforge",
                    username,
                    decision.reason
                );
            });
        }
    }

    private BridgeControlResult executeControl(net.minecraft.server.MinecraftServer server, BridgeControlCommand command) throws Exception {
        if (server == null) return BridgeControlResult.failed("minecraft_server_unavailable");
        if ("server.shutdown".equals(command.type())) {
            String reason = safeLine(command.payload().getOrDefault("reason", "Shutdown requested by NeverLauncher"), 512);
            Thread thread = new Thread(() -> {
                try { Thread.sleep(1500L); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                server.execute(() -> {
                    runtime.publishEvent("server.shutdown", Map.of("reason", reason, "source", "control-api"));
                    server.halt(false);
                });
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

    private BridgeControlResult executeControlOnServerThread(net.minecraft.server.MinecraftServer server, BridgeControlCommand command) {
        Map<String,String> payload = command.payload();
        switch (command.type()) {
            case "player.kick" -> {
                String username = safeUsername(payload.get("username"));
                var player = server.getPlayerList().getPlayerByName(username);
                if (player == null) return BridgeControlResult.failed("player_not_online");
                player.connection.disconnect(Component.literal(safeLine(payload.getOrDefault("reason", "Disconnected by server operator"), 512)));
                return BridgeControlResult.ok(Map.of("username", username));
            }
            case "message.broadcast" -> {
                String message = safeLine(payload.getOrDefault("message", ""), 1024);
                int recipients = server.getPlayerCount();
                server.getPlayerList().broadcastSystemMessage(Component.literal(message), false);
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
                if (!runtime.isConsoleCommandAllowed(raw)) return BridgeControlResult.failed("console_command_not_allowlisted");
                if (raw.isBlank() || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) return BridgeControlResult.failed("console_command_invalid");
                int code = executeMinecraftCommand(server, raw);
                return code >= 0 ? BridgeControlResult.ok(Map.of("accepted", "true", "resultCode", Integer.toString(code))) : BridgeControlResult.failed("platform_command_rejected");
            }
            default -> { return BridgeControlResult.unsupported("unsupported_control_type"); }
        }
    }

    private static int executeMinecraftCommand(net.minecraft.server.MinecraftServer server, String command) {
        return server.getCommands().performPrefixedCommand(server.createCommandSourceStack(), command);
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

    private static Path loadedArtifactPath() {
        ModList modList = ModList.get();
        if (modList == null) return null;
        var modFileInfo = modList.getModFileById(MOD_ID);
        if (modFileInfo == null || modFileInfo.getFile() == null) return null;
        return modFileInfo.getFile().getFilePath();
    }

    private static String remoteIp(Connection connection) {
        SocketAddress address = connection == null ? null : connection.getRemoteAddress();
        if (address instanceof InetSocketAddress inet) {
            if (inet.getAddress() != null) return inet.getAddress().getHostAddress();
            return inet.getHostString();
        }
        return address == null ? "" : address.toString();
    }
}
