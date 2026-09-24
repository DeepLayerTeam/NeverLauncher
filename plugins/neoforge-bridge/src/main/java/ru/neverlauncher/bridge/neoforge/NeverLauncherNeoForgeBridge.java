package ru.neverlauncher.bridge.neoforge;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.entity.player.PlayerNegotiationEvent;
import net.neoforged.neoforge.event.server.ServerStartedEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import org.slf4j.Logger;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.modloader.ModLoaderBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

@Mod(NeverLauncherNeoForgeBridge.MOD_ID)
public final class NeverLauncherNeoForgeBridge {
    public static final String MOD_ID = "neverlauncher_serverbridge";
    private static final Logger LOGGER = LogUtils.getLogger();
    private final ModLoaderBridgeRuntime runtime;

    public NeverLauncherNeoForgeBridge(IEventBus modEventBus, ModContainer modContainer) {
        Path configPath = FMLPaths.CONFIGDIR.get()
            .resolve("neverlauncher-neoforge-bridge")
            .resolve("config.yml");
        this.runtime = new ModLoaderBridgeRuntime(
            "neoforge", "NeoForge", configPath, NeverLauncherNeoForgeBridge.class, LOGGER
        );
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
    public void onPlayerNegotiation(PlayerNegotiationEvent event) {
        GameProfile profile = event.getProfile();
        Connection connection = event.getConnection();
        String username = profile == null || profile.getName() == null ? "" : profile.getName().trim();
        String uuid = profile == null || profile.getId() == null ? "" : profile.getId().toString();

        if (username.isBlank()) {
            connection.disconnect(Component.literal("NeverLauncher could not resolve the login profile"));
            return;
        }

        CompletableFuture<Void> gate = runtime.validateJoinAsync(username, uuid, remoteIp(connection))
            .handle((decision, error) -> error == null && decision != null
                ? decision
                : new JoinValidationResult(false, "backend_unavailable", "{}"))
            .thenAccept(decision -> {
                if (decision.allowed) {
                    LOGGER.info("neverlauncher.join.allowed username={} serverId={} platform=neoforge", username, runtime.serverId());
                    return;
                }
                connection.disconnect(Component.literal(decision.userMessage()));
                LOGGER.info("neverlauncher.join.denied username={} reason={} platform=neoforge", username, decision.reason);
            });

        event.enqueueWork(gate);
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
