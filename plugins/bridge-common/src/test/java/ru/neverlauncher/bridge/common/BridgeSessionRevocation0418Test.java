package ru.launcher.bridge.common;

/** Executable session-fencing regression checks; no Minecraft or JUnit dependency. */
public final class BridgeSessionRevocation0418Test {
    private static int checks;
    private static final String OLD = "a".repeat(64);
    private static final String NEW = "b".repeat(64);

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        BridgePlayerSessionRegistry sessions = new BridgePlayerSessionRegistry();
        check(!sessions.matches("Player", OLD), "unknown player cannot match a session");
        check(!sessions.bind("Player", "weak"), "weak session identifiers must be rejected");
        check(sessions.bind("Player", OLD), "valid ticket is bound");
        check(sessions.matches("player", OLD), "username lookup is case-insensitive");
        check(!sessions.matches("Player", NEW), "old login cannot authorize unrelated kick");
        check(!sessions.matches("Player", ""), "empty session correlation cannot bypass fencing");
        check(!sessions.matches("Player", "not-a-token"), "malformed correlation cannot bypass fencing");
        check(!sessions.matches("Other", OLD), "different username cannot reuse same ticket");
        check(sessions.bind("PLAYER", NEW), "relogin replaces the bound session");
        check(!sessions.matches("Player", OLD), "delayed revocation must not kick new login");
        check(sessions.matches("player", NEW), "current connection can still be targeted");
        sessions.clear("Player");
        check(!sessions.matches("player", NEW), "disconnect removes the active session");
        System.out.println("BridgeSessionRevocation0418: " + checks + " passed");
    }
}
