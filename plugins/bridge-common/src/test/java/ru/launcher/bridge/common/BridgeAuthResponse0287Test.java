package ru.launcher.bridge.common;

import java.time.Instant;
import java.util.List;

/** Runnable without JUnit/Minecraft to protect the production join decoder. */
public final class BridgeAuthResponse0287Test {
    private static final String UUID = "123e4567-e89b-42d3-a456-426614174000";
    private static final String CORRELATION = "a".repeat(64);
    private static int checks;

    private static void assertAllowed(boolean expected, BridgeAuthResponse0287.Decision actual, String scenario) {
        checks++;
        if (actual.allowed() != expected) throw new AssertionError(scenario + ": " + actual);
    }

    private static String join(String data) { return "{\"apiVersion\":\"v3\",\"data\":" + data + "}"; }
    private static String validJoin() {
        return "{\"allowed\":true,\"serverId\":\"proxy-1\",\"username\":\"Player\","
            + "\"authorization\":\"direct-ticket\",\"player\":{\"uuid\":\"" + UUID + "\"},"
            + "\"sessionCorrelationId\":\"" + CORRELATION + "\"}";
    }
    private static String validHandoff() {
        return "{\"status\":\"handoff-created\",\"sourceNodeId\":\"proxy-1\",\"targetNodeId\":\"paper-2\","
            + "\"username\":\"Player\",\"sessionCorrelationId\":\"" + CORRELATION + "\","
            + "\"handoffId\":\"ho_" + "b".repeat(32) + "\",\"expiresAt\":\"" + Instant.now().plusSeconds(30) + "\"}";
    }
    public static void main(String[] args) {
        assertAllowed(true, BridgeAuthResponse0287.join(200, join(validJoin()), "proxy-1", "player", UUID.replace("-", "")), "valid direct join");
        assertAllowed(true, BridgeAuthResponse0287.join(200, join(validJoin().replace("direct-ticket", "proxy-handoff")), "proxy-1", "Player", ""), "pre-login UUID unknown");
        assertAllowed(false, BridgeAuthResponse0287.join(403, join(validJoin()), "proxy-1", "Player", UUID), "HTTP forbidden");
        assertAllowed(false, BridgeAuthResponse0287.join(200, "{\"error\":{\"allowed\":true},\"data\":{\"allowed\":false}}", "proxy-1", "Player", UUID), "nested allowed injection");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin().replace("\"allowed\":true", "\"allowed\":true,\"allowed\":true")), "proxy-1", "Player", UUID), "duplicate allowed key");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin()), "different-node", "Player", UUID), "foreign node response");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin()), "proxy-1", "OtherPlayer", UUID), "foreign player response");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin()), "proxy-1", "Player", "123e4567-e89b-42d3-a456-426614174001"), "wrong authenticated UUID");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin().replace("\"player\":", "\"ignoredPlayer\":")), "proxy-1", "Player", UUID), "missing authoritative identity");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin().replace(CORRELATION, "invalid")), "proxy-1", "Player", UUID), "missing correlation");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin().replace("\"direct-ticket\"", "\"admin-override\"")), "proxy-1", "Player", UUID), "untrusted authorization");
        assertAllowed(false, BridgeAuthResponse0287.join(200, join(validJoin()) + "{}", "proxy-1", "Player", UUID), "trailing JSON");
        assertAllowed(true, BridgeAuthResponse0287.handoff(201, join(validHandoff()), "proxy-1", "Player", "paper-2", CORRELATION), "signed handoff response");
        assertAllowed(false, BridgeAuthResponse0287.handoff(201, join(validHandoff()), "proxy-1", "Player", "paper-3", CORRELATION), "foreign handoff target");
        assertAllowed(false, BridgeAuthResponse0287.handoff(201, join(validHandoff()), "proxy-1", "Player", "paper-2", "c".repeat(64)), "wrong handoff session");
        assertAllowed(false, BridgeAuthResponse0287.handoff(201, join(validHandoff().replace("handoff-created", "not-created")), "proxy-1", "Player", "paper-2", CORRELATION), "uncommitted handoff");
        assertAllowed(false, BridgeAuthResponse0287.handoff(201, join(validHandoff().replace("ho_" + "b".repeat(32), "ho_weak")), "proxy-1", "Player", "paper-2", CORRELATION), "invalid handoff ID");
        assertAllowed(false, BridgeAuthResponse0287.handoff(201, join(validHandoff().replaceAll("(?<=expiresAt\\\":\\\")[^\\\"]+", Instant.now().minusSeconds(1).toString())), "proxy-1", "Player", "paper-2", CORRELATION), "expired handoff");
        checks++;
        if (!BridgeAuthResponse0287.matchesAuthenticatedUUID(UUID, UUID.replace("-", ""))) throw new AssertionError("valid authenticated UUID rejected");
        checks++;
        if (BridgeAuthResponse0287.matchesAuthenticatedUUID("", UUID)) throw new AssertionError("unknown authenticated UUID accepted");
        System.out.println("BridgeAuthResponse0287: " + checks + " passed");
    }
}
