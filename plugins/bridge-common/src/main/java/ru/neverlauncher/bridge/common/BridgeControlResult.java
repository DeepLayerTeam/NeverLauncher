package ru.neverlauncher.bridge.common;

import java.util.Map;

public record BridgeControlResult(String status, Map<String,String> result, String error) {
    public BridgeControlResult {
        status = status == null ? "failed" : status.trim().toLowerCase();
        if (!java.util.Set.of("accepted","executed","succeeded","failed","unsupported","indeterminate").contains(status)) status = "failed";
        result = result == null ? Map.of() : Map.copyOf(result);
        error = error == null ? "" : error.replace('\r',' ').replace('\n',' ').trim();
        if (error.length() > 1024) error = error.substring(0,1024);
    }
    /** The platform handler returned normally; no postcondition was observed. */
    public static BridgeControlResult ok(Map<String,String> result){ return new BridgeControlResult("executed",result,""); }
    /** A delayed or queued action was accepted, but its effect is still unobserved. */
    public static BridgeControlResult accepted(Map<String,String> result){ return new BridgeControlResult("accepted",result,""); }
    /** Only call after reading the actual postcondition back from the platform. */
    public static BridgeControlResult verified(Map<String,String> observed){
        java.util.HashMap<String,String> evidence = new java.util.HashMap<>(observed);
        evidence.put("verification", "platform-state-read");
        return new BridgeControlResult("succeeded", evidence, "");
    }
    public static BridgeControlResult failed(String error){ return new BridgeControlResult("failed",Map.of(),error); }
    public static BridgeControlResult unsupported(String error){ return new BridgeControlResult("unsupported",Map.of(),error); }
    public static BridgeControlResult indeterminate(String error){ return new BridgeControlResult("indeterminate",Map.of(),error); }
}
