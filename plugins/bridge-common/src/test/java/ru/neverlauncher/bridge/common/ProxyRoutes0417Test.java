package ru.launcher.bridge.common;

import java.time.Instant;

/** No framework needed: exercises the production route-response parser. */
public final class ProxyRoutes0417Test {
    private static int checks;
    private static final String HASH = "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-30T20:00:00Z");

    private static String item(String node, String backend, String state, String health,
                               int players, int capacity, int slots, Instant observed) {
        return "{\"nodeId\":\"" + node + "\",\"backendName\":\"" + backend +
            "\",\"runtimeId\":\"" + HASH + "\",\"runtimeEpoch\":4," +
            "\"routingRevision\":7,\"routingDigest\":\"" + HASH +
            "\",\"state\":\"" + state + "\",\"health\":\"" + health +
            "\",\"playersOnline\":" + players + ",\"capacityMax\":" + capacity +
            ",\"availableSlots\":" + slots + ",\"observedAt\":\"" + observed +
            "\",\"lastHeartbeatAt\":\"" + observed + "\"}";
    }
    private static String response(String... items) {
        return "{\"data\":{\"sourceNodeId\":\"proxy-1\",\"freshnessSeconds\":90,\"items\":[" +
            String.join(",", items) + "]}}";
    }
    private static void assertRoute(boolean allowed, String reason, String body, String target) {
        BridgeAuthResponse0287.Decision decision = BridgeAuthResponse0287.route(200, body, "proxy-1", target, NOW);
        if (decision.allowed() != allowed || (!reason.isBlank() && !reason.equals(decision.reason())))
            throw new AssertionError("target=" + target + " expected=" + allowed + "/" + reason + " actual=" + decision);
        checks++;
    }
    public static void main(String[] args) {
        String normal = item("world-1", "survival", "ready", "healthy", 12, 100, 88, NOW.minusSeconds(5));
        String other = item("world-2", "creative", "ready", "degraded", 3, 100, 97, NOW.minusSeconds(10));
        assertRoute(true, "route_allowed", response(normal, other), "survival");
        assertRoute(true, "route_allowed", response(normal, other), "WORLD-2");
        assertRoute(true, "route_allowed", response(normal, other), "creative");
        assertRoute(false, "target_not_routable", response(normal), "absent");
        assertRoute(false, "target_not_routable", response(item("world-1", "survival", "draining", "healthy", 0, 40, 40, NOW)), "survival");
        assertRoute(false, "target_not_routable", response(item("world-1", "survival", "maintenance", "healthy", 0, 40, 40, NOW)), "survival");
        assertRoute(false, "target_not_routable", response(item("world-1", "survival", "ready", "unhealthy", 0, 40, 40, NOW)), "survival");
        assertRoute(false, "target_capacity_unavailable", response(item("world-1", "survival", "ready", "healthy", 40, 40, 0, NOW)), "survival");
        assertRoute(false, "target_route_stale", response(item("world-1", "survival", "ready", "healthy", 0, 40, 40, NOW.minusSeconds(91))), "survival");
        assertRoute(false, "target_route_stale", response(item("world-1", "survival", "ready", "healthy", 0, 40, 40, NOW.plusSeconds(6))), "survival");
        assertRoute(false, "ambiguous_route", response(normal, normal), "survival");
        assertRoute(false, "routing_source_mismatch", response(normal).replace("proxy-1", "other-proxy"), "survival");
        assertRoute(false, "routing_source_mismatch", "{\"error\":{\"nodeId\":\"survival\"},\"data\":{}}", "survival");
        assertRoute(false, "routing_table_invalid", response(normal).replace("\"runtimeEpoch\":4", "\"runtimeEpoch\":\"4\""), "survival");
        assertRoute(false, "routing_table_invalid", response(normal).replace("\"runtimeEpoch\":4", "\"runtimeEpoch\":4,\"runtimeEpoch\":4"), "survival");
        assertRoute(false, "routing_table_invalid", response(normal).replace("\"runtimeEpoch\":4", "\"runtimeEpoch\":4.2"), "survival");
        assertRoute(false, "route_runtime_invalid", response(normal).replace("\"runtimeEpoch\":4", "\"runtimeEpoch\":0"), "survival");
        assertRoute(false, "routing_table_invalid", response(normal).replace("\"items\":[", "\"items\":{\"ignored\":"), "survival");
        if (BridgeAuthResponse0287.route(503, response(normal), "proxy-1", "survival", NOW).allowed())
            throw new AssertionError("503 must fail closed");
        checks++;
        System.out.println("ProxyRoutes0417Test OK " + checks + " checks");
    }
}
