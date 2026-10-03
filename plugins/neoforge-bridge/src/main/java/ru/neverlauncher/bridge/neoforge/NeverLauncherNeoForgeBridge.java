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
import net.neoforged.neoforge.event.tick.ServerTickEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.server.ServerLifecycleHooks;
import org.slf4j.Logger;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgeRuntimeProbe;
import ru.neverlauncher.bridge.common.BridgeTickSampler;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.modloader.ModLoaderBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
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
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher NeoForge ServerBridge failed to start", e);
        }
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        runtime.close();
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
