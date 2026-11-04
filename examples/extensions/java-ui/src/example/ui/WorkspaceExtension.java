package example.ui;

import java.util.Map;
import ru.launcher.sdk.core.Extension;
import ru.launcher.sdk.core.ExtensionContext;
import ru.launcher.sdk.core.JsonSchema;

/** Одна JVM обслуживает обе изолированные поверхности UI и существующую цель CLI. */
public final class WorkspaceExtension implements Extension {
    private static final JsonSchema SETTINGS=JsonSchema.parse("""
        {"type":"object","properties":{"theme":{"type":"string","enum":["light","dark"]}},
         "required":["theme"],"additionalProperties":false}
        """);
    @Override public void start(ExtensionContext context) {
        var ui=context.runtime().ui();
        ui.registerSetting("admin","appearance",SETTINGS,Map.of("theme","dark"));
        ui.registerSetting("desktop","appearance",SETTINGS,Map.of("theme","light"));
        ui.registerAction("admin","refresh",null,(actor,payload)->Map.of("ok",true,"actor",actor.get("id"),
            "extension",context.manifest().id(),"surface","admin"));
        ui.registerAction("desktop","refresh",null,(actor,payload)->Map.of("ok",true,"actor",actor.get("id"),
            "extension",context.manifest().id(),"surface","desktop"));
        context.runtime().commands().register("status",null,raw->raw,params->Map.of("ok",true,
            "extension",context.manifest().id(),"version",context.manifest().versionText()));
    }
    @Override public void stop(ExtensionContext context) {}
}
