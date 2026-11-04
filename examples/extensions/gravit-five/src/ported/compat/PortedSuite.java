package ported.compat;

import java.time.Duration;
import java.util.*;
import ru.launcher.sdk.core.*;

/** Native Java source port: provider selection, synchronous veto, durable config and commands.
 * Actual identities and content are loaded via the authenticated Go document broker. */
public final class PortedSuite implements Extension {
    @Override public void start(ExtensionContext ctx) throws Exception {
        var providers = ctx.providers();
        providers.register(new ProviderDescriptor<>(IdentityServices.CONTRACT, "legacy-password", SemVer.parse("1.0.0"), "^1.0.0", "^1.0.0", LegacyAccounts::new));
        providers.register(new ProviderDescriptor<>(ContentServices.CONTRACT, "legacy-libraries", SemVer.parse("1.0.0"), "^1.0.0", "^1.0.0", LegacyLibraries::new));
        providers.select(IdentityServices.CONTRACT.id(), "legacy-password", Duration.ofSeconds(2));
        providers.select(ContentServices.CONTRACT.id(), "legacy-libraries", Duration.ofSeconds(2));
        // This is a *pre-commit* policy hook wired to real Profile.create/update in the Go API.
        ctx.runtime().events().subscribeHook("profile.before-save", null, Json::object, event -> {
            Map<String,Object> payload = event.event().payload();
            Map<String,Object> p = Json.object(payload.get("profile"));
            String loader = Json.string(p, "loader", true);
            String version = Json.string(p, "loaderVersion", false);
            if (!Set.of("vanilla", "forge", "neoforge", "fabric", "quilt").contains(loader))
                return RuntimeEvents.HookDecision.deny("unsupported loader");
            if (!loader.equals("vanilla") && version.isBlank())
                return RuntimeEvents.HookDecision.deny("loader version is required");
            Object major = p.get("javaMajor");
            if (major instanceof Number n && n.intValue() > 0 && n.intValue() < 17)
                return RuntimeEvents.HookDecision.deny("unsupported Java runtime");
            return RuntimeEvents.HookDecision.allow();
        });
        ctx.runtime().stateMigrations().register("0.49.4", "0.49.5", (config, storage) -> {
            // Migrated documents are checkpointed and restored by the Go update manager.
            Object existing = storage.get("ported-settings", null).orElse(Map.of("updates", 0L));
            Map<String,Object> data = new LinkedHashMap<>(Json.object(existing));
            data.put("schema", 2L);
            storage.put("ported-settings", data, null);
        });
        ctx.runtime().commands().register("ported-status", null, Json::object, input -> {
            var out = new LinkedHashMap<String,Object>();
            out.put("identity", providers.selected(IdentityServices.CONTRACT.id()).isPresent());
            out.put("content", providers.selected(ContentServices.CONTRACT.id()).isPresent());
            out.put("config", ctx.runtime().storage().get("ported-settings", null).orElse(Map.of()));
            return out;
        });
        ctx.runtime().commands().register("ported-save", null, Json::object, input -> {
            // Explicit extension-scoped configuration mutation; the Go broker checks permission.
            Map<String,Object> current = Json.object(ctx.runtime().storage().get("ported-settings", null).orElse(Map.of()));
            long count = current.get("updates") instanceof Number n ? n.longValue() : 0;
            if (count < 0 || count > 1_000_000) throw new IllegalStateException("invalid persisted counter");
            Map<String,Object> next = new LinkedHashMap<>(current);
            next.put("updates", count + 1);
            ctx.runtime().storage().put("ported-settings", next, null);
            return next;
        });
    }
    @Override public void stop(ExtensionContext ctx) {} // SDK drains providers and callbacks.
}
