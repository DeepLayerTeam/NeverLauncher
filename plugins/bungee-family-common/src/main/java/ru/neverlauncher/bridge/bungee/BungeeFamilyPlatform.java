package ru.neverlauncher.bridge.bungee;

import net.md_5.bungee.api.ProxyServer;

import java.util.Locale;

public enum BungeeFamilyPlatform {
    BUNGEECORD("bungeecord", "BungeeCord"),
    WATERFALL("waterfall", "Waterfall"),
    UNKNOWN("unknown", "Unknown Bungee-compatible proxy");

    private final String id;
    private final String displayName;

    BungeeFamilyPlatform(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    public String id() { return id; }
    public String displayName() { return displayName; }

    public static BungeeFamilyPlatform detect(ProxyServer proxy) {
        String brand = ((proxy == null ? "" : proxy.getName()) + " " + (proxy == null ? "" : proxy.getVersion())).toLowerCase(Locale.ROOT);
        if (brand.contains("waterfall")) return WATERFALL;
        if (brand.contains("bungeecord")) return BUNGEECORD;
        return UNKNOWN;
    }
}
