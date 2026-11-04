package example.spi;

import example.terms.Terms;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import ru.launcher.sdk.core.*;

/** Расширение JVM-хоста использует НАСТОЯЩУЮ конфигурацию брокера для выбора активного SPI. */
public final class GreetingExtension implements Extension {
    private static final ProviderService<GreetingProvider> GREETINGS =
            new ProviderService<>("example.greetings", GreetingProvider.class, SemVer.parse("1.1.0"));
    private final AtomicBoolean stopped = new AtomicBoolean();
    @Override public void start(ExtensionContext context) throws Exception {
        register(context, "friendly", Terms::friendly);
        register(context, "formal", Terms::formal);
        String initial = context.runtime().config().get("spi.active", null)
                .map(value -> {
                    if (!(value instanceof String s)) throw new IllegalArgumentException("SPI config must be string");
                    return s;
                }).orElseThrow(() -> new IllegalStateException("persisted spi.active selection required"));
        context.providers().select(GREETINGS.id(), initial, Duration.ofSeconds(2));
        context.runtime().commands().register("greet", null, payload -> Json.object(payload), input -> {
            Object operation=input.getOrDefault("operation", "call");
            if ("select".equals(operation)) {
                String next=Json.string(input,"provider",true);
                context.providers().select(GREETINGS.id(),next,Duration.ofMillis(800));
            } else if (!"call".equals(operation)) throw new IllegalArgumentException("unsupported operation");
            String name=Json.string(input,"name",false);
            if (name == null || name.isBlank()) name="World";
            final String inputName=name;
            String result=context.providers().call(GREETINGS, provider -> provider.greet(inputName));
            return Map.of("active",context.providers().selected(GREETINGS.id()).orElseThrow().providerId(),"message",result);
        });
    }
    private void register(ExtensionContext context, String id, java.util.function.Function<String,String> greeting) {
        context.providers().register(new ProviderDescriptor<>(GREETINGS, id, SemVer.parse("1.0.0"),
                ">=1.0.0 <2.0.0", "^1.0.0", () -> new GreetingProvider() {
                    private boolean live;
                    public void start(ProviderContext p) throws Exception {
                        p.cancellation().throwIfCancelled();
                        // Обнаружение сервисов в сторонних библиотеках использует TCCL.
                        if (!"example.terms.Terms".equals(Class.forName("example.terms.Terms", true,
                                Thread.currentThread().getContextClassLoader()).getName()))
                            throw new IllegalStateException("SPI dependency classloader mismatch");
                        live=true;
                    }
                    public void stop(ProviderContext p) { live=false; System.out.println("SPI_PROVIDER_STOP:" + id); }
                    public String greet(String name) {
                        if(!live)throw new IllegalStateException("provider is stopped");
                        return greeting.apply(name);
                    }
                }));
    }
    @Override public void stop(ExtensionContext context) {
        stopped.set(true);
        System.out.println("SPI_EXTENSION_STOP");
        if(context.providers().selected(GREETINGS.id()).isEmpty())
            throw new IllegalStateException("active SPI provider missing before graceful shutdown");
    }
}
