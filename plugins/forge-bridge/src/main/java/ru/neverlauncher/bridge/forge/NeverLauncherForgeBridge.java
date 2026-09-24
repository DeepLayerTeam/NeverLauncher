package ru.neverlauncher.bridge.forge;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import net.minecraftforge.event.server.ServerStartedEvent;
import net.minecraftforge.event.server.ServerStoppingEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.fml.loading.FMLPaths;
import org.slf4j.Logger;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.modloader.ModLoaderBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

@Mod(NeverLauncherForgeBridge.MOD_ID)
public final class NeverLauncherForgeBridge {
    public static final String MOD_ID = "neverlauncher_serverbridge";
    private static final Logger LOGGER = LogUtils.getLogger();
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
                    LOGGER.info("neverlauncher.join.allowed username={} serverId={} platform=forge", username, runtime.serverId());
                    return;
                }
                connection.disconnect(Component.literal(decision.userMessage()));
                LOGGER.info("neverlauncher.join.denied username={} reason={} platform=forge", username, decision.reason);
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
