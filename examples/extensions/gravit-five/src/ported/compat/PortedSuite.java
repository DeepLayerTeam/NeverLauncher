package ported.compat;

import java.time.Duration;
import java.util.*;
import ru.launcher.sdk.core.*;

/** Нативный перенос исходников Java: выбор провайдера, синхронный запрет, долговечные конфигурация и команды.
 * Реальные идентичности и содержимое загружаются через аутентифицированного брокера документов Go. */
public final class PortedSuite implements Extension {
    @Override public void start(ExtensionContext ctx) throws Exception {
        var providers = ctx.providers();
        providers.register(new ProviderDescriptor<>(IdentityServices.CONTRACT, "legacy-password", SemVer.parse("1.0.0"), "^1.0.0", "^1.0.0", LegacyAccounts::new));
        providers.register(new ProviderDescriptor<>(ContentServices.CONTRACT, "legacy-libraries", SemVer.parse("1.0.0"), "^1.0.0", "^1.0.0", LegacyLibraries::new));
        providers.select(IdentityServices.CONTRACT.id(), "legacy-password", Duration.ofSeconds(2));
        providers.select(ContentServices.CONTRACT.id(), "legacy-libraries", Duration.ofSeconds(2));
        // Это перехват политики ДО фиксации, подключённый к настоящим Profile.create/update в Go API.
        ctx.runtime().events().subscribeHook("profile.before-save", null, Json::object, event -> {
            Map<String,Object> payload = event.event().payload();
            Map<String,Object> p = Json.object(payload.get("profile"));
            String loader = Json.string(p, "loader", true);
            String version = Json.string(p, "loaderVersion", false);
            if (!Set.of("vanilla", "forge", "neoforge", "fabric", "quilt").contains(loader))
                return RuntimeEvents.HookDecision.deny("Неподдерживаемый загрузчик");
            if (!loader.equals("vanilla") && version.isBlank())
                return RuntimeEvents.HookDecision.deny("Требуется версия загрузчика");
            Object major = p.get("javaMajor");
            if (major instanceof Number n && n.intValue() > 0 && n.intValue() < 17)
                return RuntimeEvents.HookDecision.deny("Неподдерживаемая среда Java");
            return RuntimeEvents.HookDecision.allow();
        });
        ctx.runtime().stateMigrations().register("0.49.4", "0.49.5", (config, storage) -> {
            // Мигрированные документы сохраняются в контрольную точку и восстанавливаются менеджером обновлений Go.
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
            // Явное изменение конфигурации в области расширения; брокер Go проверяет разрешение.
            Map<String,Object> current = Json.object(ctx.runtime().storage().get("ported-settings", null).orElse(Map.of()));
            long count = current.get("updates") instanceof Number n ? n.longValue() : 0;
            if (count < 0 || count > 1_000_000) throw new IllegalStateException("Недопустимое сохранённое значение счётчика");
            Map<String,Object> next = new LinkedHashMap<>(current);
            next.put("updates", count + 1);
            ctx.runtime().storage().put("ported-settings", next, null);
            return next;
        });
    }
    @Override public void stop(ExtensionContext ctx) {} // SDK дожидается завершения провайдеров и обратных вызовов.
}
