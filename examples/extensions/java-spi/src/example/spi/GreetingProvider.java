package example.spi;

import ru.launcher.sdk.core.JavaProvider;

/** Пример стороннего типа SPI, остающегося интерфейсом между реализациями. */
public interface GreetingProvider extends JavaProvider {
    String greet(String name);
}
