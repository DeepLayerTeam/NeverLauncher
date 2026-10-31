package ru.launcher.bridge.common;

import java.util.Map;

/** Runnable Java 21 regression for the production control receipt contract. */
public final class BridgeControlResult0411Test {
    private static void status(String expected, BridgeControlResult actual) {
        if (!expected.equals(actual.status())) throw new AssertionError(expected + " != " + actual.status());
    }

    public static void main(String[] args) {
        status("accepted", BridgeControlResult.accepted(Map.of("scheduled", "true")));
        status("executed", BridgeControlResult.ok(Map.of("accepted", "true")));
        BridgeControlResult observed = BridgeControlResult.verified(Map.of("mode", "maintenance", "enabled", "true"));
        status("succeeded", observed);
        if (!"platform-state-read".equals(observed.result().get("verification"))) throw new AssertionError("missing verification evidence");
        status("failed", BridgeControlResult.failed("dispatcher rejected command"));
        status("indeterminate", BridgeControlResult.indeterminate("agent crashed"));
        status("unsupported", BridgeControlResult.unsupported("capability unavailable"));
        System.out.println("BridgeControlResult0411: 6 passed");
    }
}
