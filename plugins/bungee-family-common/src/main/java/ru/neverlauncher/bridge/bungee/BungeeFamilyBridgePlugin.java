package ru.neverlauncher.bridge.bungee;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerConnectedEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.scheduler.ScheduledTask;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeControlCommand;
import ru.neverlauncher.bridge.common.BridgeControlResult;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.proxy.ProxyBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/** Общий адаптер Bungee API для артефактов BungeeCord и Waterfall. */
public abstract class BungeeFamilyBridgePlugin extends Plugin implements Listener {
    private final BungeeFamilyPlatform expectedPlatform;
    // Single in-flight handoff per authenticated player, not per destination.
    private final ConcurrentHashMap<String, Object> inFlightHandoffs = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> preparedHandoffs = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> connectedTargets = new ConcurrentHashMap<>();
    private volatile ProxyBridgeRuntime runtime;
    private volatile ScheduledTask telemetryTask;

    protected BungeeFamilyBridgePlugin(BungeeFamilyPlatform expectedPlatform) {
        this.expectedPlatform = expectedPlatform;
    }

    @Override
    public final void onEnable() {
        ProxyServer proxy = getProxy();
        BungeeFamilyPlatform actual = BungeeFamilyPlatform.detect(proxy);
        if (actual != expectedPlatform) {
            throw new IllegalStateException("NeverLauncher " + expectedPlatform.displayName() + " Bridge cannot run on detected platform " + actual.displayName() + "; install neverlauncher-" + actual.id() + "-bridge instead");
        }
        try {
            Path configPath = getDataFolder().toPath().resolve("config.yml");
            ProxyBridgeRuntime next = new ProxyBridgeRuntime(
                expectedPlatform.id(), expectedPlatform.displayName(), configPath, getClass(), getLogger(),
                () -> BridgeRuntimeDescriptor.of(
                    "proxy-multi-version",
                    expectedPlatform.id(),
                    expectedPlatform.displayName(),
                    safe(proxy.getVersion()),
                    (safe(proxy.getName()) + " " + safe(proxy.getVersion())).trim(),
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
                        "proxy.bungee-api"
                    )
                )
            );
            next.start();
            runtime = next;
            next.startControlChannel(this::executeControl);
            scheduleTelemetry(proxy, next);
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher ServerBridge initialization failed: " + e.getMessage(), e);
        }
        proxy.getPluginManager().registerListener(this, this);
        proxy.getPluginManager().registerCommand(this, new BridgeCommand());
    }

    @Override
    public final void onDisable() {
        ScheduledTask task = telemetryTask;
        telemetryTask = null;
        if (task != null) task.cancel();
        ProxyBridgeRuntime current = runtime;
        runtime = null;
        if (current != null) current.close();
        preparedHandoffs.clear();
        inFlightHandoffs.clear();
        connectedTargets.clear();
        getProxy().getPluginManager().unregisterListeners(this);
        getProxy().getPluginManager().unregisterCommands(this);
    }


    private void scheduleTelemetry(ProxyServer proxy, ProxyBridgeRuntime current) {
        collectTelemetry(proxy, current);
        telemetryTask = proxy.getScheduler().schedule(
            this,
            () -> {
                ProxyBridgeRuntime active = runtime;
                if (active != null) collectTelemetry(proxy, active);
            },
            Math.max(5, current.telemetrySampleIntervalSeconds()),
            Math.max(5, current.telemetrySampleIntervalSeconds()),
            TimeUnit.SECONDS
        );
    }

    private void collectTelemetry(ProxyServer proxy, ProxyBridgeRuntime current) {
        int online = Math.max(0, proxy.getOnlineCount());
        int max = online;
        try {
            Object config = proxy.getConfig();
            Object value = config.getClass().getMethod("getPlayerLimit").invoke(config);
            if (value instanceof Number number) max = Math.max(online, number.intValue());
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Для пользовательских реализаций семейства Bungee ограничение числа игроков необязательно.
        }
        current.recordPlatformTelemetry(BridgePlatformTelemetry.proxy(
            online, Math.max(0, max),
            java.util.List.of("players", "proxy.bungee")
        ));
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public final void onPreLogin(PreLoginEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null) {
            event.setCancelled(true);
            event.setCancelReason(TextComponent.fromLegacyText("NeverLauncher ServerBridge is not ready"));
            return;
        }
        event.registerIntent(this);
        String username = event.getConnection().getName();
        // UUID at PreLogin is not yet a verified online/project identity.
        // The signed Backend ticket is checked here; its UUID is compared
        // after game authentication in onAuthenticatedLogin below.
        String uuid = "";
        String ip = remoteIP(event.getConnection().getSocketAddress());
        current.validateJoinAsync(username, uuid, ip, getProxy().getConfig().isOnlineMode()).whenComplete((result, error) -> {
            try {
                JoinValidationResult finalResult = error == null && result != null
                    ? result
                    : new JoinValidationResult(false, error instanceof CompletionException ? "backend_unavailable" : "bridge_runtime_unavailable", "{}");
                current.publishEvent("player.login", Map.of(
                    "username", username,
                    "allowed", Boolean.toString(finalResult.allowed),
                    "reason", finalResult.reason == null ? "" : finalResult.reason
                ));
                if (!finalResult.allowed) {
                    event.setCancelled(true);
                    event.setCancelReason(TextComponent.fromLegacyText(finalResult.userMessage()));
                    getLogger().info("neverlauncher.join.denied username=" + username + " reason=" + finalResult.reason + " platform=" + expectedPlatform.id());
                } else {
                    getLogger().info("neverlauncher.join.allowed username=" + username + " serverId=" + current.serverId() + " platform=" + expectedPlatform.id());
                }
            } finally {
                event.completeIntent(this);
            }
        });
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public final void onAuthenticatedLogin(LoginEvent event) {
        ProxyBridgeRuntime current = runtime;
        String username = event.getConnection().getName();
        String uuid = event.getConnection().getUniqueId() == null ? "" : event.getConnection().getUniqueId().toString();
        if (current == null || !current.confirmAuthenticatedPlayer(username, uuid)) {
            event.setCancelled(true);
            event.setCancelReason(TextComponent.fromLegacyText(
                "NeverLauncher authenticated Minecraft UUID does not match the launcher session"));
            getLogger().warning("neverlauncher.join.uuid-denied username=" + username + " platform=" + expectedPlatform.id());
        }
    }

    @EventHandler
    public final void onPlayerDisconnect(PlayerDisconnectEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null) return;
        String username = event.getPlayer().getName();
        current.publishEvent("player.quit", Map.of("username", username));
        current.playerDisconnected(username);
        String playerKey = username.toLowerCase(Locale.ROOT);
        inFlightHandoffs.remove(playerKey);
        connectedTargets.remove(playerKey);
        preparedHandoffs.keySet().removeIf(key -> key.startsWith(playerKey + "\u0000"));
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public final void onServerConnect(ServerConnectEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (event.isCancelled() || event.getTarget() == null) return;
        if (current == null) { event.setCancelled(true); return; }
        final var player = event.getPlayer();
        final String username = player.getName();
        final String playerKey = username.toLowerCase(Locale.ROOT);
        final String target = event.getTarget().getName();
        final String key = playerKey + "\u0000" + target.toLowerCase(Locale.ROOT);
        final Long preparedUntil = preparedHandoffs.remove(key);
        if (preparedUntil != null) {
            // Never manufacture a second one-time handoff for a timed-out internal
            // connect; Backend may already have committed or consumed the first.
            if (preparedUntil < System.currentTimeMillis()) event.setCancelled(true);
            return;
        }
        // Cancel the original event before asynchronous authorization. Bungee's
        // synchronous event cannot be resumed by an HTTP callback.
        event.setCancelled(true);
        final Object token = new Object();
        if (inFlightHandoffs.putIfAbsent(playerKey, token) != null) return;
        final var serverInfo = event.getTarget();
        final var reason = event.getReason();
        current.createHandoffAsync(username, target).whenComplete((result, error) -> {
            final JoinValidationResult decision = error == null && result != null
                ? result : new JoinValidationResult(false, "backend_unavailable", "{}");
            // API calls and player state are consulted only on the proxy scheduler.
            try {
                getProxy().getScheduler().schedule(this, () -> {
                    if (inFlightHandoffs.get(playerKey) != token) return;
                    if (runtime != current || getProxy().getPlayer(username) != player) {
                        inFlightHandoffs.remove(playerKey, token);
                        return;
                    }
                    if (!decision.allowed) {
                        inFlightHandoffs.remove(playerKey, token);
                        player.sendMessage(TextComponent.fromLegacyText(
                            "NeverLauncher handoff denied: " + decision.reason));
                        getLogger().info("neverlauncher.handoff.denied username=" + username +
                            " target=" + target + " reason=" + decision.reason);
                        return;
                    }
                    // A backend route can disappear between ticket creation and
                    // connect. Never silently try another server with this ticket.
                    if (getProxy().getServerInfo(target) != serverInfo) {
                        inFlightHandoffs.remove(playerKey, token);
                        player.sendMessage(TextComponent.fromLegacyText("NeverLauncher target topology changed"));
                        return;
                    }
                    preparedHandoffs.put(key, System.currentTimeMillis() + 30_000L);
                    try {
                        player.connect(serverInfo, (success, throwable) -> {
                            preparedHandoffs.remove(key);
                            inFlightHandoffs.remove(playerKey, token);
                            if (!success) getLogger().warning("neverlauncher.handoff.connect-failed username=" +
                                username + " target=" + target);
                        }, reason);
                    } catch (RuntimeException failure) {
                        preparedHandoffs.remove(key);
                        inFlightHandoffs.remove(playerKey, token);
                        getLogger().warning("neverlauncher.handoff.connect-error target=" + target +
                            " error=" + failure.getMessage());
                    }
                }, 0L, TimeUnit.MILLISECONDS);
            } catch (RuntimeException failure) {
                inFlightHandoffs.remove(playerKey, token);
                getLogger().warning("neverlauncher.handoff.schedule-error target=" + target);
            }
        });
    }

    /** Connected is emitted only when the proxy has actually established
     * a backend connection. The HTTP handoff being accepted is not success. */
    @EventHandler
    public final void onServerConnected(ServerConnectedEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null || event.getServer() == null || event.getServer().getInfo() == null) return;
        String username = event.getPlayer().getName();
        String playerKey = username.toLowerCase(Locale.ROOT);
        String target = event.getServer().getInfo().getName();
        String source = connectedTargets.put(playerKey, target);
        if (source != null && source.equalsIgnoreCase(target)) return;
        current.publishEvent(source == null ? "proxy.connect" : "proxy.switch", Map.of(
            "username", username, "source", source == null ? "" : source, "target", target));
    }

    private BridgeControlResult executeControl(BridgeControlCommand command) {
        Map<String,String> payload = command.payload();
        switch (command.type()) {
            case "player.kick" -> {
                String username = safeUsername(payload.get("username"));
                var player = getProxy().getPlayer(username);
                if (player == null) return BridgeControlResult.failed("player_not_online");
                String correlation = payload.getOrDefault("sessionCorrelationId", "");
                if (!correlation.isBlank() && (runtime == null || !runtime.matchesPlayerSession(
                    username, player.getUniqueId() == null ? "" : player.getUniqueId().toString(), correlation)))
                    return BridgeControlResult.failed("player_session_changed");
                player.disconnect(TextComponent.fromLegacyText(safeLine(payload.getOrDefault("reason", "Disconnected by proxy operator"), 512)));
                return BridgeControlResult.ok(Map.of("username", username));
            }
            case "message.broadcast" -> {
                int recipients = getProxy().getOnlineCount();
                getProxy().broadcast(TextComponent.fromLegacyText(safeLine(payload.getOrDefault("message", ""), 1024)));
                return BridgeControlResult.ok(Map.of("recipients", Integer.toString(recipients)));
            }
            case "server.shutdown" -> {
                String reason = safeLine(payload.getOrDefault("reason", "Shutdown requested by NeverLauncher"), 512);
                getProxy().getScheduler().schedule(this, () -> getProxy().stop(reason), 1500L, TimeUnit.MILLISECONDS);
                return BridgeControlResult.accepted(Map.of("scheduled", "true", "graceMillis", "1500"));
            }
            case "server.console" -> {
                String raw = payload.getOrDefault("command", "").trim();
                if (raw.startsWith("/")) raw = raw.substring(1);
                ProxyBridgeRuntime current = runtime;
                if (current == null || !current.isConsoleCommandAllowed(raw)) return BridgeControlResult.failed("console_command_not_allowlisted");
                if (raw.isBlank() || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) return BridgeControlResult.failed("console_command_invalid");
                boolean accepted = getProxy().getPluginManager().dispatchCommand(getProxy().getConsole(), raw);
                return accepted ? BridgeControlResult.ok(Map.of("accepted", "true")) : BridgeControlResult.failed("platform_command_rejected");
            }
            case "whitelist.add", "whitelist.remove", "whitelist.enable", "whitelist.disable", "ban.add", "ban.remove", "server.save" -> {
                return BridgeControlResult.unsupported("operation_not_supported_by_bungee_core");
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

    private static String safe(String value) {
        return value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').trim();
    }

    private static String remoteIP(SocketAddress address) {
        if (!(address instanceof InetSocketAddress inet) || inet.getAddress() == null) return "";
        return inet.getAddress().getHostAddress();
    }

    private final class BridgeCommand extends Command {
        private BridgeCommand() {
            super("nlbridge", "neverlauncher.bridge.status");
        }

        @Override
        public void execute(CommandSender sender, String[] args) {
            ProxyBridgeRuntime current = runtime;
            if (current == null) {
                sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher ServerBridge is not initialized"));
                return;
            }
            String sub = args.length == 0 ? "status" : args[0].toLowerCase(Locale.ROOT);
            switch (sub) {
                case "status" -> sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher " + expectedPlatform.displayName() + " Bridge " + BridgeDefaults.VERSION + " serverId=" + current.serverId() + " backend=" + current.backendUrl() + " heartbeat=" + current.heartbeatStatus()));
                case "test" -> {
                    if (!sender.hasPermission("neverlauncher.bridge.admin")) {
                        sender.sendMessage(TextComponent.fromLegacyText("Недостаточно прав: neverlauncher.bridge.admin"));
                        return;
                    }
                    current.triggerHeartbeat();
                    sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher heartbeat queued; last=" + current.heartbeatStatus()));
                }
                case "reload" -> {
                    if (!sender.hasPermission("neverlauncher.bridge.reload")) {
                        sender.sendMessage(TextComponent.fromLegacyText("Недостаточно прав: neverlauncher.bridge.reload"));
                        return;
                    }
                    try {
                        current.reload();
                        sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher bridge configuration reloaded; serverId=" + current.serverId() + " nodeKeyFingerprint=" + current.fingerprint()));
                    } catch (Exception e) {
                        sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher reload failed; previous runtime kept active: " + e.getMessage()));
                    }
                }
                case "diagnostics" -> {
                    if (!sender.hasPermission("neverlauncher.bridge.diagnostics")) {
                        sender.sendMessage(TextComponent.fromLegacyText("Недостаточно прав: neverlauncher.bridge.diagnostics"));
                        return;
                    }
                    sender.sendMessage(TextComponent.fromLegacyText("NeverLauncher diagnostics: detected=" + BungeeFamilyPlatform.detect(getProxy()).id() + ", " + current.diagnostics()));
                }
                default -> sender.sendMessage(TextComponent.fromLegacyText("Команды: /nlbridge status | test | reload | diagnostics"));
            }
        }
    }
}
