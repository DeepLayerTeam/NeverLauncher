package ru.neverlauncher.bridge.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import net.kyori.adventure.text.Component;
import ru.neverlauncher.bridge.common.BridgeConfig;
import ru.neverlauncher.bridge.common.BridgeDefaults;
import ru.neverlauncher.bridge.common.BridgeIntegrity;
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;

import java.nio.file.Path;
import java.util.logging.Logger;

@Plugin(id = BridgeDefaults.VELOCITY_ID, name = "NeverLauncher Velocity Bridge", version = BridgeDefaults.VERSION, authors = {"SkiF4er"})
public final class NeverLauncherVelocityBridge {
    private final Logger logger = Logger.getLogger("NeverLauncherVelocityBridge");
    private BridgeConfig config = BridgeConfig.fromEnv();
    private NeverLauncherApiClient api = new NeverLauncherApiClient(config);

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            Path configPath = Path.of("plugins", "neverlauncher-velocity", "config.yml");
            config = BridgeConfig.load(configPath);
            String pluginSha256 = BridgeIntegrity.artifactSha256(NeverLauncherVelocityBridge.class);
            api = new NeverLauncherApiClient(config, "velocity", BridgeDefaults.VERSION, pluginSha256);
            boolean ok = api.heartbeat("velocity", BridgeDefaults.VERSION);
            logger.info("NeverLauncher Velocity Bridge " + BridgeDefaults.VERSION + " initialized; heartbeat=" + ok + "; backend=" + config.backendUrl + "; serverId=" + config.serverId + "; sha256=" + (pluginSha256.isBlank() ? "unavailable" : pluginSha256.substring(0, 12)));
        } catch (Exception e) {
            logger.warning("NeverLauncher Velocity Bridge config load failed: " + e.getMessage());
        }
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        JoinValidationResult result = api.validateJoin(username, username, "");
        if (!result.allowed) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(result.userMessage())));
            logger.info("neverlauncher.join.denied username=" + username + " reason=" + result.reason);
            return;
        }
        logger.info("neverlauncher.join.allowed username=" + username + " serverId=" + config.serverId);
    }
}
