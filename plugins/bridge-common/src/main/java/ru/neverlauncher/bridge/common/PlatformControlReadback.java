package ru.neverlauncher.bridge.common;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;

/** Reads Minecraft server state after a command, never inferring success from dispatcher return values. */
public final class PlatformControlReadback {
    private PlatformControlReadback() {}

    public static BridgeControlResult whitelistEntry(Object server, String username, boolean expected) {
        Object manager = playerManager(server);
        Object entries = call(manager, "getWhitelist", "getWhiteList");
        Boolean observed = namedEntry(entries, username);
        return entryResult("whitelisted", username, expected, observed);
    }

    public static BridgeControlResult banEntry(Object server, String username, boolean expected) {
        Object manager = playerManager(server);
        Object entries = call(manager, "getBannedPlayers", "getUserBanList", "getBans", "getBannedProfiles", "getBannedPlayersList");
        Boolean observed = namedEntry(entries, username);
        return entryResult("banned", username, expected, observed);
    }

    public static BridgeControlResult whitelistMode(Object server, boolean expected) {
        Object manager = playerManager(server);
        Object value = call(manager, "isWhitelistEnabled", "isUsingWhitelist", "isWhiteListEnabled", "hasWhitelist");
        if (!(value instanceof Boolean observed)) return BridgeControlResult.ok(Map.of("enabled", Boolean.toString(expected)));
        if (observed != expected) return BridgeControlResult.failed("whitelist_mode_postcondition_mismatch");
        return BridgeControlResult.verified(Map.of("enabled", Boolean.toString(observed)));
    }

    private static BridgeControlResult entryResult(String key, String username, boolean expected, Boolean observed) {
        Map<String,String> evidence = Map.of("username", username, key, Boolean.toString(expected));
        if (observed == null) return BridgeControlResult.ok(evidence);
        if (observed != expected) return BridgeControlResult.failed(key + "_postcondition_mismatch");
        return BridgeControlResult.verified(evidence);
    }

    private static Object playerManager(Object server) {
        return call(server, "getPlayerManager", "getPlayerList");
    }

    /** A null result is deliberately inconclusive (unknown API or ambiguous collection). */
    private static Boolean namedEntry(Object configList, String username) {
        if (configList == null || username == null) return null;
        Object names = call(configList, "getNames", "getUserList");
        if (names == null) return null;
        if (names instanceof String[] strings) {
            for (String name : strings) if (name.equalsIgnoreCase(username)) return true;
            return false;
        }
        if (names.getClass().isArray()) {
            for (int i=0;i<Array.getLength(names);i++) {
                Object v = Array.get(names,i);
                if (!(v instanceof String)) return null;
                if (((String)v).equalsIgnoreCase(username)) return true;
            }
            return false;
        }
        if (names instanceof Iterable<?> iterable) {
            for (Object value : iterable) {
                if (!(value instanceof String)) return null;
                if (((String)value).equalsIgnoreCase(username)) return true;
            }
            return false;
        }
        return null;
    }

    private static Object call(Object target, String... methods) {
        if (target == null) return null;
        for (String method : methods) {
            try {
                Method callable = target.getClass().getMethod(method);
                Object value = callable.invoke(target);
                if (value instanceof Optional<?> optional) value = optional.orElse(null);
                if (value != null) return value;
            } catch (NoSuchMethodException ignored) {
                // Loader API differs; don't claim a verified result.
            } catch (IllegalAccessException | InvocationTargetException | SecurityException e) {
                return null;
            }
        }
        return null;
    }
}
