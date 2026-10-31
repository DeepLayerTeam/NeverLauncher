package ru.example.launcher;

import java.util.*;
import ru.launcher.sdk.core.*;

/** Executable sample: backend receives typed events; CLI reads the SAME state through Go. */
public final class RuntimeExample implements Extension {
    private static final JsonSchema SETTINGS=JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"enabled\":{\"type\":\"boolean\"}},\"required\":[\"enabled\"],\"additionalProperties\":false}");
    private static final JsonSchema RELEASE=JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"version\":{\"type\":\"string\",\"minLength\":1}},\"required\":[\"version\"],\"additionalProperties\":false}");
    record VersionEvent(String version){}
    @Override public void start(ExtensionContext ctx)throws Exception {
        RuntimeServices runtime=Objects.requireNonNull(ctx.runtime(),"Java Runtime APIs are required");
        RuntimeDocuments config=runtime.config();
        if(config.get("settings",SETTINGS).isEmpty())config.put("settings",Map.of("enabled",true),SETTINGS);
        runtime.commands().register("status",JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"args\":{\"type\":\"array\",\"maxItems\":0}}}"),
            raw->Json.object(raw),args->Map.of("settings",config.get("settings",SETTINGS).orElseThrow(),"lastRelease",runtime.storage().get("last-release",RELEASE).orElse(Map.of())));
        if("backend".equals(System.getenv().getOrDefault("LAUNCHER_EXTENSION_TARGET","backend"))) {
            runtime.events().subscribe("release.published","async",RELEASE,raw->new VersionEvent(Json.string(Json.object(raw),"version",true)),event->{
                runtime.storage().put("last-release",Map.of("version",event.payload().version()),RELEASE);
            });
        }
    }
    @Override public void stop(ExtensionContext ctx){}
}
