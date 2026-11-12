package ru.launcher.bridge.common;

/** Version-neutral entry point; the established BridgeAuthResponse0287 API remains supported. */
public final class BridgeAuthResponse {
    private BridgeAuthResponse() {}
    public static BridgeAuthResponse0287.Decision join(int status, String body, String nodeId, String username, String uuid) {
        return BridgeAuthResponse0287.join(status, body, nodeId, username, uuid);
    }
    public static BridgeAuthResponse0287.Decision handoff(int status, String body, String nodeId, String target, String correlation) {
        return BridgeAuthResponse0287.handoff(status, body, nodeId, target, correlation);
    }
    public static BridgeAuthResponse0287.Decision route(int status, String body, String source, String target, java.time.Instant now) {
        return BridgeAuthResponse0287.route(status, body, source, target, now);
    }
    public static boolean matchesAuthenticatedUUID(String authenticated, String expected) {
        return BridgeAuthResponse0287.matchesAuthenticatedUUID(authenticated, expected);
    }
}
