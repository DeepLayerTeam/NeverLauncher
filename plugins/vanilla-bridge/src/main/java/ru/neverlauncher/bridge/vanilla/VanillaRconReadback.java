package ru.launcher.bridge.vanilla;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses only unambiguous English Mojang RCON list replies; other locales are inconclusive. */
final class VanillaRconReadback {
    private static final Pattern COUNT = Pattern.compile("(?i)^There are (\\d+) (whitelisted player(?:\\(s\\)|s)?|ban(?:\\(s\\)|s)?|banned players?)(?:\\s*:\\s*(.*))?\\s*$");
    private static final Pattern NONE = Pattern.compile("(?i)^There are no (?:whitelisted player(?:\\(s\\)|s)?|ban(?:\\(s\\)|s)?|banned players?)\\.?$");

    private VanillaRconReadback() {}

    static boolean rejected(String response) {
        if (response == null) return false;
        String s = response.trim().toLowerCase(java.util.Locale.ROOT);
        return s.startsWith("unknown or incomplete command") || s.startsWith("unknown command") ||
            s.startsWith("incorrect argument") || s.startsWith("no player was found") ||
            s.startsWith("that player does not exist") || s.startsWith("nothing changed");
    }

    static Boolean membership(String type, String username, String response) {
        if (response == null || username == null || !username.matches("[A-Za-z0-9_]{1,16}")) return null;
        String value = response.trim();
        if (NONE.matcher(value).matches()) {
            boolean whitelist = value.toLowerCase(java.util.Locale.ROOT).contains("whitelisted");
            return whitelist == type.startsWith("whitelist.") ? false : null;
        }
        Matcher count = COUNT.matcher(value);
        if (!count.matches()) return null;
        boolean whitelistedResponse = count.group(2).toLowerCase(java.util.Locale.ROOT).startsWith("whitelisted");
        if (whitelistedResponse != type.startsWith("whitelist.")) return null;
        int expected;
        try { expected = Integer.parseInt(count.group(1)); } catch (NumberFormatException e) { return null; }
        if (expected == 0) return false;
        if (expected > 200000 || count.group(3) == null || count.group(3).isBlank()) return null;
        String[] users = count.group(3).split(",\\s*");
        // Avoid false negatives if RCON reply was truncated or contains an unsupported format.
        if (users.length != expected) return null;
        for (String user : users) {
            if (!user.matches("[A-Za-z0-9_]{1,16}")) return null;
            if (user.equalsIgnoreCase(username)) return true;
        }
        return false;
    }
}
