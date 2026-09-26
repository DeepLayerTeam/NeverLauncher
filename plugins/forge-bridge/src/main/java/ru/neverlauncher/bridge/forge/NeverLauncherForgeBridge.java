package ru.neverlauncher.bridge.forge;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.PacketListener;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.Packet;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerCommonPacketListenerImpl;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.network.GatherLoginConfigurationTasksEvent;
import net.minecraftforge.event.server.ServerStartedEvent;
import net.minecraftforge.event.server.ServerStoppingEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.fml.loading.FMLPaths;
import net.minecraftforge.network.config.ConfigurationTaskContext;
import net.minecraftforge.server.ServerLifecycleHooks;
import org.slf4j.Logger;
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

    public NeverLauncherForgeBridge(FMLJavaModLoadingContext context) {
        Path configPath = FMLPaths.CONFIGDIR.get()
            .resolve("neverlauncher-forge-bridge")
            .resolve("config.yml");
        this.runtime = new ModLoaderBridgeRuntime(
            "forge", "Forge", configPath, NeverLauncherForgeBridge.class, LOGGER
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

    private static String remoteIp(Connection connection) {
        SocketAddress address = connection == null ? null : connection.getRemoteAddress();
        if (address instanceof InetSocketAddress inet) {
            if (inet.getAddress() != null) return inet.getAddress().getHostAddress();
            return inet.getHostString();
        }
        return address == null ? "" : address.toString();
    }
}
