package example.developer;

import java.util.Map;
import ru.launcher.sdk.core.Extension;
import ru.launcher.sdk.core.ExtensionContext;
import ru.launcher.sdk.core.JsonSchema;

/** Внешний потребитель SDK: одно подписанное расширение предоставляет обработчики Admin, Desktop и CLI. */
public final class DeveloperExtension implements Extension {
    private static final JsonSchema THEME = JsonSchema.parse("""
        {"type":"object", "properties":{"theme":{"type":"string","enum":["light","dark"]}},
         "required":["theme"], "additionalProperties":false}
        """);
    @Override public void start(ExtensionContext context) {
        var ui = context.runtime().ui();
        ui.registerSetting("admin", "appearance", THEME, Map.of("theme", "dark"));
        ui.registerSetting("desktop", "appearance", THEME, Map.of("theme", "light"));
        ui.registerAction("admin", "refresh", null, (actor, payload) ->
            Map.of("ok", true, "actor", actor.get("id"), "extension", context.manifest().id(), "surface", "admin"));
        ui.registerAction("desktop", "refresh", null, (actor, payload) ->
            Map.of("ok", true, "actor", actor.get("id"), "extension", context.manifest().id(), "surface", "desktop"));
        context.runtime().commands().register("status", null, value -> value, args ->
            Map.of("ok", true, "extension", context.manifest().id(), "version", context.manifest().versionText()));
    }
    @Override public void stop(ExtensionContext context) {}
}
