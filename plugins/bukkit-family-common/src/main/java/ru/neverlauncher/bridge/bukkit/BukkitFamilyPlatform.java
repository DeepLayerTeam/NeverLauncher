package ru.neverlauncher.bridge.bukkit;

import org.bukkit.Bukkit;

import java.util.Locale;

/**
 * Runtime discriminator for the Bukkit-compatible server family.
 *
 * The bridge deliberately compiles against the Bukkit/Spigot API only. Paper,
 * Purpur and Folia detection uses brand/class probes without linking their APIs,
 * so the same common runtime remains binary-compatible with plain CraftBukkit.
 */
public enum BukkitFamilyPlatform {
    BUKKIT("bukkit", "Bukkit"),
    SPIGOT("spigot", "Spigot"),
    PAPER("paper", "Paper"),
    PURPUR("purpur", "Purpur"),
    FOLIA("folia", "Folia");

    private final String id;
    private final String displayName;

    BukkitFamilyPlatform(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    public String id() { return id; }
    public String displayName() { return displayName; }

    public static BukkitFamilyPlatform detect() {
        String brand = safeLower(Bukkit.getName()) + " " + safeLower(Bukkit.getVersion());
        if (brand.contains("folia") || classPresent("io.papermc.paper.threadedregions.RegionizedServer")) {
            return FOLIA;
        }
        if (brand.contains("purpur") || classPresent("org.purpurmc.purpur.PurpurConfig")) {
            return PURPUR;
        }
        if (brand.contains("paper") || classPresent("io.papermc.paper.ServerBuildInfo") || classPresent("com.destroystokyo.paper.PaperConfig")) {
            return PAPER;
        }
        if (brand.contains("spigot") || classPresent("org.spigotmc.SpigotConfig")) {
            return SPIGOT;
        }
        return BUKKIT;
    }

    private static boolean classPresent(String name) {
        try {
            Class.forName(name, false, BukkitFamilyPlatform.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError ignored) {
            return false;
        }
    }

    private static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }
}
