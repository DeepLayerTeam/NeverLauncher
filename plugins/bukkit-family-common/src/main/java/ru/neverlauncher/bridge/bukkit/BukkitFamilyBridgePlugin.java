package ru.neverlauncher.bridge.bukkit;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;
import ru.neverlauncher.bridge.common.NodeIdentity;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Production Bukkit-family ServerBridge runtime shared by CraftBukkit, Spigot,
 * Paper, Purpur and Folia artifacts.
 *
 * No Bukkit scheduler is used for network I/O. Heartbeats run on a dedicated
 * daemon executor, which avoids main-thread stalls on classic servers and avoids
 * illegal global/region scheduler assumptions on Folia. Login validation runs in
 * AsyncPlayerPreLoginEvent and must complete before the server accepts the login.
 */
public abstract class BukkitFamilyBridgePlugin extends JavaPlugin implements Listener, CommandExecutor {
    private final BukkitFamilyPlatform expectedPlatform;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private volatile RuntimeState runtime;
    private volatile boolean lastHeartbeatOK;
    private volatile Instant lastHeartbeatAt;
    private ScheduledExecutorService networkExecutor;

    protected BukkitFamilyBridgePlugin(BukkitFamilyPlatform expectedPlatform) {
        this.expectedPlatform = expectedPlatform;
    }

    @Override
    public final void onEnable() {
        BukkitFamilyPlatform actual = BukkitFamilyPlatform.detect();
        if (actual != expectedPlatform) {
            getLogger().severe("NeverLauncher " + expectedPlatform.displayName() + " Bridge cannot run on detected platform " + actual.displayName() + ". Install neverlauncher-" + actual.id() + "-bridge instead.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        try {
            runtime = loadRuntime();
        } catch (Exception e) {
            getLogger().severe("NeverLauncher ServerBridge initialization failed: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("nlbridge") != null) getCommand("nlbridge").setExecutor(this);

        networkExecutor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "neverlauncher-bridge-io-" + expectedPlatform.id());
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((t, error) -> getLogger().severe("NeverLauncher bridge I/O worker failed: " + error.getMessage()));
            return thread;
        });
        scheduleHeartbeat(0);

        RuntimeState state = runtime;
        getLogger().info("NeverLauncher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
            " enabled; serverId=" + state.config.serverId +
            "; nodeKeyFingerprint=" + state.identity.fingerprint() +
            "; sha256=" + shortHash(state.pluginSha256) +
            "; foliaSafeIO=true");
    }

    @Override
    public final void onDisable() {
        stopping.set(true);
        ScheduledExecutorService executor = networkExecutor;
        if (executor != null) {
            executor.shutdownNow();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    getLogger().warning("NeverLauncher bridge I/O worker did not terminate within shutdown window");
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
        if (state == null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, "NeverLauncher ServerBridge is not ready");
            return;
        }
        String ip = event.getAddress() == null ? "" : event.getAddress().getHostAddress();
        JoinValidationResult result = state.api.validateJoin(event.getName(), String.valueOf(event.getUniqueId()), ip);
        if (!result.allowed) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, result.userMessage());
            getLogger().info("neverlauncher.join.denied username=" + event.getName() + " reason=" + result.reason + " platform=" + expectedPlatform.id());
            return;
        }
        getLogger().info("neverlauncher.join.allowed username=" + event.getName() + " serverId=" + state.config.serverId + " platform=" + expectedPlatform.id());
    }

    @Override
    public final boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length == 0 ? "status" : args[0].toLowerCase(Locale.ROOT);
        RuntimeState state = runtime;
        if (state == null) {
            sender.sendMessage("NeverLauncher ServerBridge is not initialized");
            return true;
        }
        switch (sub) {
            case "status" -> {
                sender.sendMessage("NeverLauncher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION +
                    " serverId=" + state.config.serverId + " backend=" + state.config.backendUrl +
                    " heartbeat=" + heartbeatStatus());
                return true;
            }
            case "test" -> {
                if (!sender.hasPermission("neverlauncher.bridge.admin")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.admin");
                    return true;
                }
                triggerHeartbeat();
                sender.sendMessage("NeverLauncher heartbeat queued; last=" + heartbeatStatus());
                return true;
            }
            case "reload" -> {
                if (!sender.hasPermission("neverlauncher.bridge.reload")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.reload");
                    return true;
                }
                try {
                    RuntimeState next = loadRuntime();
                    runtime = next;
                    triggerHeartbeat();
                    sender.sendMessage("NeverLauncher bridge configuration reloaded; serverId=" + next.config.serverId + " nodeKeyFingerprint=" + next.identity.fingerprint());
                } catch (Exception e) {
                    sender.sendMessage("NeverLauncher reload failed; previous runtime kept active: " + e.getMessage());
                }
                return true;
            }
            case "diagnostics" -> {
                if (!sender.hasPermission("neverlauncher.bridge.diagnostics")) {
                    sender.sendMessage("Недостаточно прав: neverlauncher.bridge.diagnostics");
                    return true;
                }
                sender.sendMessage("NeverLauncher diagnostics: platform=" + expectedPlatform.id() +
                    ", detected=" + BukkitFamilyPlatform.detect().id() +
                    ", failMode=" + state.config.failMode +
                    ", requireLauncherSession=" + state.config.requireLauncherSession +
                    ", requireIntegrity=" + state.config.requireIntegrity +
                    ", project=" + state.config.projectId + "/" + state.config.profileId + "/" + state.config.channel +
                    ", heartbeatIntervalSeconds=" + state.config.heartbeatIntervalSeconds +
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
            throw new IllegalStateException("cannot measure running plugin JAR SHA-256");
        }
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        NeverLauncherApiClient api = new NeverLauncherApiClient(config, identity, expectedPlatform.id(), BridgeDefaults.VERSION, pluginSha256);
        return new RuntimeState(config, identity, api, pluginSha256);
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
                getLogger().info("NeverLauncher " + expectedPlatform.displayName() + " Bridge heartbeat=true serverId=" + state.config.serverId);
            } else {
                getLogger().warning("NeverLauncher " + expectedPlatform.displayName() + " Bridge heartbeat=false serverId=" + state.config.serverId + " reason=rejected_or_unavailable");
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

    private record RuntimeState(BridgeConfig config, NodeIdentity identity, NeverLauncherApiClient api, String pluginSha256) {}
}
