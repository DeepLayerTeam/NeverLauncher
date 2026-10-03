package ru.neverlauncher.bridge.forge;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.PacketListener;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.Packet;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.event.network.GatherLoginConfigurationTasksEvent;
import net.minecraftforge.event.server.ServerStartedEvent;
import net.minecraftforge.event.server.ServerStoppingEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.ModList;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.fml.loading.FMLPaths;
import net.minecraftforge.network.config.ConfigurationTaskContext;
import net.minecraftforge.server.ServerLifecycleHooks;
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

@Mod(NeverLauncherForgeBridge.MOD_ID)
public final class NeverLauncherForgeBridge {
    public static final String MOD_ID = "neverlauncher_serverbridge";
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final ConfigurationTask.Type JOIN_VALIDATION_TASK =
        new ConfigurationTask.Type("neverlauncher:join_validation");

    private final ModLoaderBridgeRuntime runtime;
    private final BridgeTickSampler tickSampler = new BridgeTickSampler();
    private long lastTelemetrySampleAt;

    public NeverLauncherForgeBridge(FMLJavaModLoadingContext context) {
        Path configPath = FMLPaths.CONFIGDIR.get()
            .resolve("neverlauncher-forge-bridge")
            .resolve("config.yml");
        this.runtime = new ModLoaderBridgeRuntime(
            "forge", "Forge", configPath, NeverLauncherForgeBridge.class, NeverLauncherForgeBridge::loadedArtifactPath, LOGGER,
            () -> {
                String loaderVersion = BridgeRuntimeProbe.nestedStaticString("net.minecraftforge.fml.loading.FMLLoader", "versionInfo", "forgeVersion");
                if (loaderVersion.isBlank()) loaderVersion = BridgeRuntimeProbe.packageVersion("net.minecraftforge.fml.loading.FMLLoader");
                String minecraftVersion = BridgeRuntimeProbe.nestedStaticString("net.minecraftforge.fml.loading.FMLLoader", "versionInfo", "mcVersion");
                if (minecraftVersion.isBlank()) minecraftVersion = BridgeRuntimeProbe.minecraftVersion();
                return BridgeRuntimeDescriptor.of(
                    minecraftVersion, "forge", "Forge", loaderVersion,
                    loaderVersion.isBlank() ? "Forge" : "Forge " + loaderVersion,
                    java.util.List.of(
                        "heartbeat.signed",
                        "join.configuration-task-gate",
                        "artifact.sha256",
                        "artifact.loader-owned",
                        "runtime.discovery",
                        "runtime.ed25519-attestation",
                        "telemetry.server-v1",
                        "loader.forge"
                    )
                );
            }
        );
        MinecraftForge.EVENT_BUS.register(this);
    }

    @SubscribeEvent
    public void onServerStarted(ServerStartedEvent event) {
        try {
            runtime.start();
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher Forge ServerBridge failed to start", e);
        }
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        runtime.close();
    }

    @SubscribeEvent
    public void onServerTickPre(TickEvent.ServerTickEvent.Pre event) {
        tickSampler.onTickStart();
    }

    @SubscribeEvent
    public void onServerTickPost(TickEvent.ServerTickEvent.Post event) {
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

    @SubscribeEvent
    public void onGatherLoginConfigurationTasks(GatherLoginConfigurationTasksEvent event) {
        Connection connection = event.getConnection();
        PacketListener listener = connection.getPacketListener();
        if (!(listener instanceof ServerCommonPacketListenerImpl serverListener)) {
            connection.disconnect(Component.literal("NeverLauncher could not resolve the login listener"));
            return;
        }

        GameProfile profile = serverListener.getOwner();
        String username = profile == null || profile.getName() == null ? "" : profile.getName().trim();
        String uuid = profile == null || profile.getId() == null ? "" : profile.getId().toString();
        event.addTask(new JoinValidationTask(username, uuid));
    }

    private final class JoinValidationTask implements ConfigurationTask {
        private final String username;
        private final String uuid;

        private JoinValidationTask(String username, String uuid) {
            this.username = username;
            this.uuid = uuid;
        }

        @Override
        public void start(ConfigurationTaskContext ctx) {
            if (username.isBlank()) {
                ctx.getConnection().disconnect(Component.literal("NeverLauncher could not resolve the login profile"));
                return;
            }

            runtime.validateJoinAsync(username, uuid, remoteIp(ctx.getConnection()))
                .handle((decision, error) -> error == null && decision != null
                    ? decision
                    : new JoinValidationResult(false, "backend_unavailable", "{}"))
                .thenAccept(decision -> completeOnServerThread(ctx, decision));
        }

        @Override
        public void start(Consumer<Packet<?>> send) {
            throw new IllegalStateException("Forge must start NeverLauncher join validation with ConfigurationTaskContext");
        }

        @Override
        public Type type() {
            return JOIN_VALIDATION_TASK;
        }

        private void completeOnServerThread(ConfigurationTaskContext ctx, JoinValidationResult decision) {
            var server = ServerLifecycleHooks.getCurrentServer();
            if (server == null) {
                ctx.getConnection().disconnect(Component.literal("NeverLauncher server is not available"));
                return;
            }

            server.execute(() -> {
                if (!ctx.getConnection().isConnected()) {
                    return;
                }
                if (decision.allowed) {
                    LOGGER.info(
                        "neverlauncher.join.allowed username={} serverId={} platform=forge",
                        username,
                        runtime.serverId()
                    );
                    ctx.finish(JOIN_VALIDATION_TASK);
                    return;
                }

                ctx.getConnection().disconnect(Component.literal(decision.userMessage()));
                LOGGER.info(
                    "neverlauncher.join.denied username={} reason={} platform=forge",
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
