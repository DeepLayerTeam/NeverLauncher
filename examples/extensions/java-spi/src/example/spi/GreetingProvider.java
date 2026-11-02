package example.spi;

import ru.launcher.sdk.core.JavaProvider;

/** Example third-party SPI type that remains an interface across implementations. */
public interface GreetingProvider extends JavaProvider {
    String greet(String name);
}
