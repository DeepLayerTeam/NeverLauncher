package ru.launcher.sdk.core;

/** Контракт жизненного цикла провайдера внутри одной аутентифицированной JVM Java-расширения.
 * Реализации — обычные Java-сервисы; привилегированные операции хоста должны использовать RuntimeServices.
 */
public interface JavaProvider {
    void start(ProviderContext context) throws Exception;
    void stop(ProviderContext context) throws Exception;
}
