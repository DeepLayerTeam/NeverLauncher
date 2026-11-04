package ru.launcher.bridge.common;

import java.util.Map;

public record BridgeControlResult(String status, Map<String,String> result, String error) {
    public BridgeControlResult {
        status = status == null ? "failed" : status.trim().toLowerCase();
        if (!java.util.Set.of("accepted","executed","succeeded","failed","unsupported","indeterminate").contains(status)) status = "failed";
        result = result == null ? Map.of() : Map.copyOf(result);
        error = error == null ? "" : error.replace('\r',' ').replace('\n',' ').trim();
        if (error.length() > 1024) error = error.substring(0,1024);
    }
    /** Обработчик платформы вернулся штатно, но фактическое последующее состояние не наблюдалось. */
    public static BridgeControlResult ok(Map<String,String> result){ return new BridgeControlResult("executed",result,""); }
    /** Отложенное действие поставлено в очередь или принято, но его эффект пока не наблюдался. */
    public static BridgeControlResult accepted(Map<String,String> result){ return new BridgeControlResult("accepted",result,""); }
    /** Вызывайте только после повторного чтения фактического последующего состояния с платформы. */
    public static BridgeControlResult verified(Map<String,String> observed){
        java.util.HashMap<String,String> evidence = new java.util.HashMap<>(observed);
        evidence.put("verification", "platform-state-read");
        return new BridgeControlResult("succeeded", evidence, "");
    }
    public static BridgeControlResult failed(String error){ return new BridgeControlResult("failed",Map.of(),error); }
    public static BridgeControlResult unsupported(String error){ return new BridgeControlResult("unsupported",Map.of(),error); }
    public static BridgeControlResult indeterminate(String error){ return new BridgeControlResult("indeterminate",Map.of(),error); }
}
