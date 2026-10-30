package ru.neverlauncher.bridge.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.Component;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeControlCommand;
import ru.neverlauncher.bridge.common.BridgeControlResult;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.BridgeRuntimeProbe;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.proxy.ProxyBridgeRuntime;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

@Plugin(id = BridgeDefaults.VELOCITY_ID, name = "NeverLauncher Velocity Bridge", version = BridgeDefaults.VERSION, authors = {"SkiF4er"})
public final class NeverLauncherVelocityBridge {
    private final Logger logger = Logger.getLogger("NeverLauncherVelocityBridge");
    private final ProxyServer proxy;
    private volatile ProxyBridgeRuntime runtime;
    private volatile ScheduledTask telemetryTask;
    // Hold the reservation until a real connection is observed or until the
    // original short-lived one-time ticket has expired.
    private record PendingTransfer(String target, long expiresAt) {}
    private final ConcurrentHashMap<String, PendingTransfer> pendingTransfers = new ConcurrentHashMap<>();

    @Inject
    public NeverLauncherVelocityBridge(ProxyServer proxy) {
        this.proxy = proxy;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            ProxyBridgeRuntime next = new ProxyBridgeRuntime(
                "velocity",
                "Velocity",
                Path.of("plugins", "neverlauncher-velocity", "config.yml"),
                NeverLauncherVelocityBridge.class,
                logger,
                () -> {
                    String velocityVersion = BridgeRuntimeProbe.packageVersion("com.velocitypowered.api.proxy.ProxyServer");
                    return BridgeRuntimeDescriptor.of(
                        "proxy-multi-version", "velocity", "Velocity", velocityVersion,
                        velocityVersion.isBlank() ? "Velocity" : "Velocity " + velocityVersion,
                        java.util.List.of(
                            "heartbeat.signed",
                            "join.proxy-prelogin-gate",
                            "handoff.one-time",
                            "artifact.sha256",
                            "runtime.discovery",
                            "runtime.ed25519-attestation",
                            "telemetry.server-v1",
                            "events.ordered-stream-v1",
                            "control.secure-channel-v1",
                            "proxy.velocity-api"
                        )
                    );
                }
            );
            next.start();
            runtime = next;
            next.startControlChannel(this::executeControl);
            scheduleTelemetry(next);
        } catch (Exception e) {
            logger.severe("NeverLauncher Velocity Bridge initialization failed: " + e.getMessage());
            throw new IllegalStateException("NeverLauncher Velocity Bridge failed closed", e);
        }
    }

    private void scheduleTelemetry(ProxyBridgeRuntime current) {
        collectTelemetry(current);
        telemetryTask = proxy.getScheduler()
            .buildTask(this, () -> {
                ProxyBridgeRuntime active = runtime;
                if (active != null) collectTelemetry(active);
            })
            .delay(Math.max(5, current.telemetrySampleIntervalSeconds()), TimeUnit.SECONDS)
            .repeat(Math.max(5, current.telemetrySampleIntervalSeconds()), TimeUnit.SECONDS)
            .schedule();
    }

    private void collectTelemetry(ProxyBridgeRuntime current) {
        int online = Math.max(0, proxy.getPlayerCount());
        int max = Math.max(online, proxy.getConfiguration().getShowMaxPlayers());
        current.recordPlatformTelemetry(BridgePlatformTelemetry.proxy(
            online, max, java.util.List.of("players", "proxy.velocity")
        ));
    }

    @Subscribe
    public EventTask onPreLogin(PreLoginEvent event) {
        return EventTask.async(() -> {
            ProxyBridgeRuntime current = runtime;
            if (current == null) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("NeverLauncher ServerBridge is not ready")));
                return;
            }
            String username = event.getUsername();
            String ip = event.getConnection().getRemoteAddress() == null || event.getConnection().getRemoteAddress().getAddress() == null
                ? ""
                : event.getConnection().getRemoteAddress().getAddress().getHostAddress();
            JoinValidationResult result = current.validateJoin(username, "", ip, proxy.getConfiguration().isOnlineMode());
            current.publishEvent("player.login", Map.of(
                "username", username,
                "allowed", Boolean.toString(result.allowed),
                "reason", result.reason == null ? "" : result.reason
            ));
            if (!result.allowed) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(result.userMessage())));
                logger.info("neverlauncher.join.denied username=" + username + " reason=" + result.reason + " platform=velocity");
                return;
            }
            logger.info("neverlauncher.join.allowed username=" + username + " serverId=" + current.serverId() + " platform=velocity");
        });
    }

    // PreLogin runs before the encrypted Minecraft/online-authlib handshake
    // has established the player's UUID. Never trust a username-only ticket
    // as the final identity: compare the authenticated platform UUID here.
    @Subscribe
    public void onAuthenticatedLogin(LoginEvent event) {
        ProxyBridgeRuntime current = runtime;
        String username = event.getPlayer().getUsername();
        String authenticatedUUID = event.getPlayer().getUniqueId() == null ? "" : event.getPlayer().getUniqueId().toString();
        if (current == null || !current.confirmAuthenticatedPlayer(username, authenticatedUUID)) {
            event.setResult(LoginEvent.ComponentResult.denied(Component.text(
                "NeverLauncher authenticated Minecraft UUID does not match the launcher session")));
            logger.warning("neverlauncher.join.uuid-denied username=" + username + " platform=velocity");
        }
    }

    @Subscribe
    public EventTask onServerPreConnect(ServerPreConnectEvent event) {
        return EventTask.async(() -> {
            ProxyBridgeRuntime current = runtime;
            if (current == null) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                return;
            }
            // Respect a prior proxy plugin's explicit deny/redirect. The ticket
            // must authorize the *actual* destination, not the original name.
            var destination = event.getResult().getServer().orElse(null);
            if (!event.getResult().isAllowed() || destination == null) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                return;
            }
            String username = event.getPlayer().getUsername();
            String key = username.toLowerCase(Locale.ROOT);
            String target = destination.getServerInfo().getName();
            long now = System.currentTimeMillis();
            PendingTransfer reservation = new PendingTransfer(target, now + 30_000L);
            PendingTransfer previous = pendingTransfers.putIfAbsent(key, reservation);
            if (previous != null) {
                if (previous.expiresAt() >= now || !pendingTransfers.replace(key, previous, reservation)) {
                    event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    return;
                }
            }
            try {
                // The Backend reads live routing state and atomically creates the
                // one-time handoff. No automatic retry after uncertain delivery.
                JoinValidationResult result = current.createHandoff(username, target);
                if (!result.allowed || runtime != current ||
                    proxy.getServer(target).orElse(null) != destination ||
                    pendingTransfers.get(key) != reservation) {
                    event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    pendingTransfers.remove(key, reservation);
                    logger.info("neverlauncher.handoff.denied username=" + username + " target=" +
                        target + " reason=" + (result.allowed ? "topology_changed" : result.reason));
                }
                if (result.allowed && runtime == current &&
                    pendingTransfers.get(key) == reservation &&
                    proxy.getServer(target).orElse(null) == destination) {
                    event.setResult(ServerPreConnectEvent.ServerResult.allowed(destination));
                }
                // Do not emit proxy.switch here. Only ServerConnectedEvent proves it.
            } catch (RuntimeException failure) {
                pendingTransfers.remove(key, reservation);
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                logger.warning("neverlauncher.handoff.failed username=" + username + " target=" + target);
            }
        });
    }

    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null) return;
        String username = event.getPlayer().getUsername();
        String target = event.getServer().getServerInfo().getName();
        pendingTransfers.computeIfPresent(username.toLowerCase(Locale.ROOT),
            (key, transfer) -> transfer.target().equalsIgnoreCase(target) ? null : transfer);
        String source = event.getPreviousServer()
            .map(connection -> connection.getServerInfo().getName()).orElse("");
        if (source.equalsIgnoreCase(target)) return;
        current.publishEvent(source.isBlank() ? "proxy.connect" : "proxy.switch", Map.of(
            "username", username, "source", source, "target", target));
    }

    private BridgeControlResult executeControl(BridgeControlCommand command) throws Exception {
        Map<String,String> payload = command.payload();
        switch (command.type()) {
            case "player.kick" -> {
                String username = safeUsername(payload.get("username"));
                var player = proxy.getPlayer(username).orElse(null);
                if (player == null) return BridgeControlResult.failed("player_not_online");
                player.disconnect(Component.text(safeLine(payload.getOrDefault("reason", "Disconnected by proxy operator"), 512)));
                return BridgeControlResult.ok(Map.of("username", username));
            }
            case "message.broadcast" -> {
                Component message = Component.text(safeLine(payload.getOrDefault("message", ""), 1024));
                int recipients = proxy.getPlayerCount();
                for (var player : proxy.getAllPlayers()) player.sendMessage(message);
                return BridgeControlResult.ok(Map.of("recipients", Integer.toString(recipients)));
            }
            case "server.shutdown" -> {
                String reason = safeLine(payload.getOrDefault("reason", "Shutdown requested by NeverLauncher"), 512);
                proxy.getScheduler().buildTask(this, () -> proxy.shutdown(Component.text(reason))).delay(1500, TimeUnit.MILLISECONDS).schedule();
                return BridgeControlResult.accepted(Map.of("scheduled", "true", "graceMillis", "1500"));
            }
            case "server.console" -> {
                String raw = payload.getOrDefault("command", "").trim();
                if (raw.startsWith("/")) raw = raw.substring(1);
                ProxyBridgeRuntime current = runtime;
                if (current == null || !current.isConsoleCommandAllowed(raw)) return BridgeControlResult.failed("console_command_not_allowlisted");
                if (raw.isBlank() || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) return BridgeControlResult.failed("console_command_invalid");
                proxy.getCommandManager().executeAsync(proxy.getConsoleCommandSource(), raw).get(10, TimeUnit.SECONDS);
                return BridgeControlResult.ok(Map.of("accepted", "true"));
            }
            case "whitelist.add", "whitelist.remove", "whitelist.enable", "whitelist.disable", "ban.add", "ban.remove", "server.save" -> {
                return BridgeControlResult.unsupported("operation_not_supported_by_velocity_core");
            }
            default -> { return BridgeControlResult.unsupported("unsupported_control_type"); }
        }
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

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null) return;
        String username = event.getPlayer().getUsername();
        current.publishEvent("player.quit", Map.of("username", username));
        current.playerDisconnected(username);
        pendingTransfers.remove(username.toLowerCase(Locale.ROOT));
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        ScheduledTask task = telemetryTask;
        telemetryTask = null;
        if (task != null) task.cancel();
        ProxyBridgeRuntime current = runtime;
        runtime = null;
        pendingTransfers.clear();
        if (current != null) current.close();
    }
}
