package ru.neverlauncher.bridge.fabric;

import com.mojang.authlib.GameProfile;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.network.ClientConnection;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;
import ru.neverlauncher.bridge.common.NodeIdentity;
import ru.neverlauncher.bridge.fabric.mixin.ServerLoginNetworkHandlerAccessor;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.time.Instant;
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
        ServerLifecycleEvents.SERVER_STARTED.register(server -> scheduleHeartbeat(0));
        ServerLifecycleEvents.SERVER_STOPPING.register(server -> close());

        RuntimeState current = state;
        LOGGER.info("NeverLauncher Fabric Server Bridge {} enabled; serverId={}; nodeKeyFingerprint={}; nodePublicKey={}; sha256={}; asyncLoginGate=true; clientModRequired=false",
            BridgeDefaults.VERSION,
            current.config.serverId,
            current.identity.fingerprint(),
            current.identity.publicKeyBase64Url(),
            shortHash(current.pluginSha256));
    }

    private void onLoginQueryStart(ServerLoginNetworkHandler handler, MinecraftServer server,
                                   net.fabricmc.fabric.api.networking.v1.LoginPacketSender sender,
                                   net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking.LoginSynchronizer synchronizer) {
        if (stopping.get()) {
            handler.disconnect(Text.literal("NeverLauncher ServerBridge is stopping"));
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
            if (decision.allowed) {
                LOGGER.info("neverlauncher.join.allowed username={} serverId={} platform=fabric", login.username, serverId());
                return CompletableFuture.completedFuture(null);
            }
            // Fabric's login synchronizer may complete off the logical server thread.
            // Disconnect on MinecraftServer's executor and keep the login gate blocked
            // until that state transition has actually been applied.
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
        NeverLauncherApiClient api = new NeverLauncherApiClient(config, identity, PLATFORM, BridgeDefaults.VERSION, pluginSha256);
        return new RuntimeState(config, identity, api, pluginSha256);
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

    private static Thread daemonThread(Runnable task, String role) {
        Thread thread = new Thread(task, "neverlauncher-fabric-bridge-" + role);
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler((t, error) -> LOGGER.error("NeverLauncher Fabric bridge {} worker failed", role, error));
        return thread;
    }

    private static String shortHash(String hash) {
        return BridgeIntegrity.isSha256(hash) ? hash.substring(0, 12) : "unavailable";
    }

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, NeverLauncherApiClient api, String pluginSha256) {}
    private record LoginIdentity(String username, String uuid, String ip) {}
}
