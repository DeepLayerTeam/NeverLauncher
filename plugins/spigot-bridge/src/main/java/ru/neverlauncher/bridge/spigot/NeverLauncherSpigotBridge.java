package ru.launcher.bridge.spigot;

import ru.launcher.bridge.bukkit.BukkitFamilyBridgePlugin;
import ru.launcher.bridge.bukkit.BukkitFamilyPlatform;

public final class LauncherSpigotBridge extends BukkitFamilyBridgePlugin {
    public LauncherSpigotBridge() {
        super(BukkitFamilyPlatform.SPIGOT);
    }
}
