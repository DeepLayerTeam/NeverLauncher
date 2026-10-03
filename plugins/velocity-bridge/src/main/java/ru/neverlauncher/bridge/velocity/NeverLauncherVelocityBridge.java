package ru.neverlauncher.bridge.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.Component;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeRuntimeDescriptor;
import ru.neverlauncher.bridge.common.BridgePlatformTelemetry;
import ru.neverlauncher.bridge.common.BridgeRuntimeProbe;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.proxy.ProxyBridgeRuntime;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.logging.Logger;

@Plugin(id = BridgeDefaults.VELOCITY_ID, name = "NeverLauncher Velocity Bridge", version = BridgeDefaults.VERSION, authors = {"SkiF4er"})
public final class NeverLauncherVelocityBridge {
    private final Logger logger = Logger.getLogger("NeverLauncherVelocityBridge");
    private final ProxyServer proxy;
    private volatile ProxyBridgeRuntime runtime;
    private volatile ScheduledTask telemetryTask;

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
                            "proxy.velocity-api"
                        )
                    );
                }
            );
            next.start();
            runtime = next;
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
            JoinValidationResult result = current.validateJoin(username, "", ip);
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

    @Subscribe
    public EventTask onServerPreConnect(ServerPreConnectEvent event) {
        return EventTask.async(() -> {
            ProxyBridgeRuntime current = runtime;
            if (current == null) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                return;
            }
            String username = event.getPlayer().getUsername();
            String target = event.getOriginalServer().getServerInfo().getName();
            String source = event.getPlayer().getCurrentServer().map(connection -> connection.getServerInfo().getName()).orElse("");
            JoinValidationResult result = current.createHandoff(username, target);
            if (!result.allowed) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                logger.info("neverlauncher.handoff.denied username=" + username + " target=" + target + " reason=" + result.reason + " platform=velocity");
                return;
            }
            current.publishEvent(source.isBlank() ? "proxy.connect" : "proxy.switch", Map.of(
                "username", username,
                "source", source,
                "target", target
            ));
            logger.info("neverlauncher.handoff.created username=" + username + " target=" + target + " source=" + current.serverId() + " platform=velocity");
        });
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        ScheduledTask task = telemetryTask;
        telemetryTask = null;
        if (task != null) task.cancel();
        ProxyBridgeRuntime current = runtime;
        runtime = null;
        if (current != null) current.close();
    }
}
