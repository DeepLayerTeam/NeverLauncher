package ru.neverlauncher.bridge.velocity;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import net.kyori.adventure.text.Component;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.proxy.ProxyBridgeRuntime;

import java.nio.file.Path;
import java.util.logging.Logger;

@Plugin(id = BridgeDefaults.VELOCITY_ID, name = "NeverLauncher Velocity Bridge", version = BridgeDefaults.VERSION, authors = {"SkiF4er"})
public final class NeverLauncherVelocityBridge {
    private final Logger logger = Logger.getLogger("NeverLauncherVelocityBridge");
    private volatile ProxyBridgeRuntime runtime;

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            ProxyBridgeRuntime next = new ProxyBridgeRuntime(
                "velocity",
                "Velocity",
                Path.of("plugins", "neverlauncher-velocity", "config.yml"),
                NeverLauncherVelocityBridge.class,
                logger
            );
            next.start();
            runtime = next;
        } catch (Exception e) {
            logger.severe("NeverLauncher Velocity Bridge initialization failed: " + e.getMessage());
            throw new IllegalStateException("NeverLauncher Velocity Bridge failed closed", e);
        }
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
            if (!result.allowed) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(result.userMessage())));
                logger.info("neverlauncher.join.denied username=" + username + " reason=" + result.reason + " platform=velocity");
                return;
            }
            logger.info("neverlauncher.join.allowed username=" + username + " serverId=" + current.serverId() + " platform=velocity");
        });
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        ProxyBridgeRuntime current = runtime;
        runtime = null;
        if (current != null) current.close();
    }
}
