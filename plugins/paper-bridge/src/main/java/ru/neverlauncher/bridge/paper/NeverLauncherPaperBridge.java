package ru.neverlauncher.bridge.paper;

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

import java.nio.file.Path;

public final class NeverLauncherPaperBridge extends JavaPlugin implements Listener, CommandExecutor {
    private BridgeConfig config;
    private NeverLauncherApiClient api;

    @Override
    public void onEnable() {
        try {
            Path configPath = getDataFolder().toPath().resolve("config.yml");
            config = BridgeConfig.load(configPath);
        } catch (Exception e) {
            config = BridgeConfig.fromEnv();
            getLogger().warning("Не удалось прочитать config.yml, используется env/default config: " + e.getMessage());
        }
        String pluginSha256 = BridgeIntegrity.artifactSha256(NeverLauncherPaperBridge.class);
        api = new NeverLauncherApiClient(config, "paper", BridgeDefaults.VERSION, pluginSha256);
        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("nlbridge") != null) getCommand("nlbridge").setExecutor(this);
        boolean ok = api.heartbeat("paper", BridgeDefaults.VERSION);
        getLogger().info("NeverLauncher Paper Bridge " + BridgeDefaults.VERSION + " enabled; heartbeat=" + ok + "; serverId=" + config.serverId + "; sha256=" + (pluginSha256.isBlank() ? "unavailable" : pluginSha256.substring(0, 12)));
    }

    @EventHandler
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress() == null ? "" : event.getAddress().getHostAddress();
        JoinValidationResult result = api.validateJoin(event.getName(), String.valueOf(event.getUniqueId()), ip);
        if (!result.allowed) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, result.userMessage());
            getLogger().info("neverlauncher.join.denied username=" + event.getName() + " reason=" + result.reason);
            return;
        }
        getLogger().info("neverlauncher.join.allowed username=" + event.getName() + " serverId=" + config.serverId);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length == 0 ? "status" : args[0].toLowerCase();
        if ("status".equals(sub)) {
            sender.sendMessage("NeverLauncher Paper Bridge " + BridgeDefaults.VERSION + " serverId=" + config.serverId + " backend=" + config.backendUrl);
            return true;
        }
        if ("test".equals(sub)) {
            sender.sendMessage("NeverLauncher Backend heartbeat: " + api.heartbeat("paper", BridgeDefaults.VERSION));
            return true;
        }
        if ("diagnostics".equals(sub)) {
            sender.sendMessage("NeverLauncher diagnostics: failMode=" + config.failMode + ", requireLauncherSession=" + config.requireLauncherSession + ", project=" + config.projectId + "/" + config.profileId + "/" + config.channel);
            return true;
        }
        sender.sendMessage("Команды: /nlbridge status | test | diagnostics");
        return true;
    }

}
