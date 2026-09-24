package ru.neverlauncher.bridge.modloader;

import org.slf4j.Logger;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;
import ru.neverlauncher.bridge.common.NodeIdentity;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ModLoaderBridgeRuntime implements AutoCloseable {
    private final String platformId;
    private final String displayName;
    private final Path configPath;
    private final Class<?> artifactAnchor;
    private final Logger logger;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final ScheduledExecutorService heartbeatExecutor;
    private final ThreadPoolExecutor validationExecutor;
    private volatile RuntimeState state;
    private volatile boolean lastHeartbeatOK;
    private volatile Instant lastHeartbeatAt;

    public ModLoaderBridgeRuntime(String platformId, String displayName, Path configPath, Class<?> artifactAnchor, Logger logger) {
        this.platformId = requireText(platformId, "platformId").toLowerCase(Locale.ROOT);
        this.displayName = requireText(displayName, "displayName");
        this.configPath = Objects.requireNonNull(configPath, "configPath").toAbsolutePath().normalize();
        this.artifactAnchor = Objects.requireNonNull(artifactAnchor, "artifactAnchor");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(task -> daemonThread(task, "heartbeat"));
        this.validationExecutor = new ThreadPoolExecutor(
            2, 8, 60L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(256),
            task -> daemonThread(task, "join"),
            new ThreadPoolExecutor.AbortPolicy()
        );
        this.validationExecutor.allowCoreThreadTimeOut(true);
    }

    public synchronized void start() throws Exception {
        if (stopping.get()) throw new IllegalStateException("runtime is stopping");
        if (state != null) return;
        state = loadState();
        scheduleHeartbeat(0);
        RuntimeState current = state;
        logger.info("NeverLauncher {} Server Bridge {} enabled; serverId={}; nodeKeyFingerprint={}; nodePublicKey={}; sha256={}; asyncLoginGate=true; clientModRequired=false",
            displayName, BridgeDefaults.VERSION, current.config.serverId, current.identity.fingerprint(),
            current.identity.publicKeyBase64Url(), shortHash(current.pluginSha256));
    }

    public CompletableFuture<JoinValidationResult> validateJoinAsync(String username, String uuid, String ip) {
        if (stopping.get() || validationExecutor.isShutdown()) {
            return CompletableFuture.completedFuture(new JoinValidationResult(false, "bridge_runtime_unavailable", "{}"));
        }
        try {
            return CompletableFuture.supplyAsync(() -> validateJoin(username, uuid, ip), validationExecutor);
        } catch (RejectedExecutionException e) {
            logger.warn("NeverLauncher {} Server Bridge join validation queue saturated; failing closed", displayName);
            return CompletableFuture.completedFuture(new JoinValidationResult(false, "bridge_overloaded", "{}"));
        }
    }

    public JoinValidationResult validateJoin(String username, String uuid, String ip) {
        RuntimeState current = state;
        if (current == null || stopping.get()) {
            return new JoinValidationResult(false, "bridge_runtime_unavailable", "{}");
        }
        return current.api.validateJoin(username, uuid, ip);
    }

    public String serverId() {
        RuntimeState current = state;
        return current == null ? "" : current.config.serverId;
    }

    public void triggerHeartbeat() {
        if (stopping.get() || heartbeatExecutor.isShutdown()) return;
        heartbeatExecutor.execute(this::heartbeatOnce);
    }

    @Override
    public void close() {
        if (!stopping.compareAndSet(false, true)) return;
        heartbeatExecutor.shutdownNow();
        validationExecutor.shutdownNow();
        try {
            boolean heartbeatStopped = heartbeatExecutor.awaitTermination(2, TimeUnit.SECONDS);
            boolean validationStopped = validationExecutor.awaitTermination(2, TimeUnit.SECONDS);
            if (!heartbeatStopped || !validationStopped) {
                logger.warn("NeverLauncher {} Server Bridge workers did not terminate within shutdown window", displayName);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        state = null;
    }

    private RuntimeState loadState() throws Exception {
        BridgeConfig config = BridgeConfig.load(configPath, platformId + "-main");
        String pluginSha256 = BridgeIntegrity.artifactSha256(artifactAnchor);
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) {
            throw new IllegalStateException("cannot measure running " + displayName + " bridge JAR SHA-256");
        }
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        NeverLauncherApiClient api = new NeverLauncherApiClient(config, identity, platformId, BridgeDefaults.VERSION, pluginSha256);
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
        boolean ok = current.api.heartbeat(platformId, BridgeDefaults.VERSION);
        boolean previous = lastHeartbeatOK;
        Instant previousAt = lastHeartbeatAt;
        lastHeartbeatOK = ok;
        lastHeartbeatAt = Instant.now();
        if (previousAt == null || previous != ok) {
            if (ok) logger.info("NeverLauncher {} Server Bridge heartbeat=true serverId={}", displayName, current.config.serverId);
            else logger.warn("NeverLauncher {} Server Bridge heartbeat=false serverId={} reason=rejected_or_unavailable", displayName, current.config.serverId);
        }
    }

    private Thread daemonThread(Runnable task, String role) {
        Thread thread = new Thread(task, "neverlauncher-" + platformId + "-bridge-" + role);
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler((t, error) ->
            logger.error("NeverLauncher {} Server Bridge {} worker failed", displayName, role, error));
        return thread;
    }

    private static String shortHash(String hash) {
        return BridgeIntegrity.isSha256(hash) ? hash.substring(0, 12) : "unavailable";
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required");
        return value.trim();
    }

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, NeverLauncherApiClient api, String pluginSha256) {}
}
