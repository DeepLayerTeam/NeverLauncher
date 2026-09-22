package ru.neverlauncher.bridge.purpur;

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
import ru.neverlauncher.bridge.common.JoinValidationResult;
import ru.neverlauncher.bridge.common.NeverLauncherApiClient;

import java.nio.file.Path;

public final class NeverLauncherPurpurBridge extends JavaPlugin implements Listener, CommandExecutor {
    private BridgeConfig config;
    private NeverLauncherApiClient api;

    @Override
    public void onEnable() {
        try {
            config = BridgeConfig.load(getDataFolder().toPath().resolve("config.yml"));
        } catch (Exception e) {
            config = BridgeConfig.fromEnv();
            getLogger().warning("Не удалось прочитать config.yml, используется env/default config: " + e.getMessage());
        }
        api = new NeverLauncherApiClient(config);
        Bukkit.getPluginManager().registerEvents(this, this);
        if (getCommand("nlbridge") != null) getCommand("nlbridge").setExecutor(this);
        boolean ok = api.heartbeat("purpur", BridgeDefaults.VERSION);
        getLogger().info("NeverLauncher Purpur Bridge " + BridgeDefaults.VERSION + " enabled; heartbeat=" + ok + "; serverId=" + config.serverId);
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
        getLogger().info("neverlauncher.join.allowed username=" + event.getName() + " serverId=" + config.serverId + " platform=purpur");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length == 0 ? "status" : args[0].toLowerCase();
        if ("status".equals(sub)) {
            sender.sendMessage("NeverLauncher Purpur Bridge " + BridgeDefaults.VERSION + " serverId=" + config.serverId + " backend=" + config.backendUrl);
            return true;
        }
        if ("test".equals(sub)) {
            sender.sendMessage("NeverLauncher Backend heartbeat: " + api.heartbeat("purpur", BridgeDefaults.VERSION));
            return true;
        }
        if ("diagnostics".equals(sub)) {
            sender.sendMessage("NeverLauncher Purpur diagnostics: failMode=" + config.failMode + ", requireLauncherSession=" + config.requireLauncherSession + ", project=" + config.projectId + "/" + config.profileId + "/" + config.channel);
            return true;
        }
        sender.sendMessage("Команды: /nlbridge status | test | diagnostics");
        return true;
    }

}
