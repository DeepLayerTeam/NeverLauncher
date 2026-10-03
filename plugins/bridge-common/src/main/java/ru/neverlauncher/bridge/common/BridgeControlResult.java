package ru.neverlauncher.bridge.common;

import java.util.Map;

public record BridgeControlResult(String status, Map<String,String> result, String error) {
    public BridgeControlResult {
        status = status == null ? "failed" : status.trim().toLowerCase();
        if (!java.util.Set.of("succeeded","failed","unsupported","indeterminate").contains(status)) status = "failed";
        result = result == null ? Map.of() : Map.copyOf(result);
        error = error == null ? "" : error.replace('\r',' ').replace('\n',' ').trim();
        if (error.length() > 1024) error = error.substring(0,1024);
    }
    public static BridgeControlResult ok(Map<String,String> result){ return new BridgeControlResult("succeeded",result,""); }
    public static BridgeControlResult failed(String error){ return new BridgeControlResult("failed",Map.of(),error); }
    public static BridgeControlResult unsupported(String error){ return new BridgeControlResult("unsupported",Map.of(),error); }
    public static BridgeControlResult indeterminate(String error){ return new BridgeControlResult("indeterminate",Map.of(),error); }
}
