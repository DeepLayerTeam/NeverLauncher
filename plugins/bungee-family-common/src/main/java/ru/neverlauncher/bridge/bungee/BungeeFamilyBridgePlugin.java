package ru.neverlauncher.bridge.bungee;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.proxy.ProxyBridgeRuntime;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/** Shared Bungee API adapter used by the BungeeCord and Waterfall artifacts. */
public abstract class BungeeFamilyBridgePlugin extends Plugin implements Listener {
    private final BungeeFamilyPlatform expectedPlatform;
    private final ConcurrentHashMap<String, Long> preparedHandoffs = new ConcurrentHashMap<>();
    private volatile ProxyBridgeRuntime runtime;

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
            ProxyBridgeRuntime next = new ProxyBridgeRuntime(expectedPlatform.id(), expectedPlatform.displayName(), configPath, getClass(), getLogger());
            next.start();
            runtime = next;
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher ServerBridge initialization failed: " + e.getMessage(), e);
        }
        proxy.getPluginManager().registerListener(this, this);
        proxy.getPluginManager().registerCommand(this, new BridgeCommand());
    }

    @Override
    public final void onDisable() {
        ProxyBridgeRuntime current = runtime;
        runtime = null;
        if (current != null) current.close();
        preparedHandoffs.clear();
        getProxy().getPluginManager().unregisterListeners(this);
        getProxy().getPluginManager().unregisterCommands(this);
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
        String uuid = event.getConnection().getUniqueId() == null ? "" : event.getConnection().getUniqueId().toString();
        String ip = remoteIP(event.getConnection().getSocketAddress());
        current.validateJoinAsync(username, uuid, ip).whenComplete((result, error) -> {
            try {
                JoinValidationResult finalResult = error == null && result != null
                    ? result
                    : new JoinValidationResult(false, error instanceof CompletionException ? "backend_unavailable" : "bridge_runtime_unavailable", "{}");
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
    public final void onServerConnect(ServerConnectEvent event) {
        ProxyBridgeRuntime current = runtime;
        if (current == null || event.isCancelled() || event.getTarget() == null) return;
        String username = event.getPlayer().getName();
        String target = event.getTarget().getName();
        String key = username.toLowerCase(Locale.ROOT) + "\u0000" + target.toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        Long preparedUntil = preparedHandoffs.remove(key);
        if (preparedUntil != null && preparedUntil >= now) return;

        event.setCancelled(true);
        ServerConnectEvent.Reason reason = event.getReason();
        current.createHandoffAsync(username, target).whenComplete((result, error) -> {
            JoinValidationResult finalResult = error == null && result != null
                ? result
                : new JoinValidationResult(false, "backend_unavailable", "{}");
            if (!finalResult.allowed) {
                getLogger().info("neverlauncher.handoff.denied username=" + username + " target=" + target + " reason=" + finalResult.reason + " platform=" + expectedPlatform.id());
                event.getPlayer().disconnect(TextComponent.fromLegacyText("NeverLauncher handoff denied: " + finalResult.reason));
                return;
            }
            preparedHandoffs.put(key, System.currentTimeMillis() + 10_000L);
            getLogger().info("neverlauncher.handoff.created username=" + username + " target=" + target + " source=" + current.serverId() + " platform=" + expectedPlatform.id());
            getProxy().getScheduler().schedule(this,
                () -> event.getPlayer().connect(event.getTarget(), (success, throwable) -> {
                    if (!success) preparedHandoffs.remove(key);
                }, reason),
                0L, TimeUnit.MILLISECONDS);
        });
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
