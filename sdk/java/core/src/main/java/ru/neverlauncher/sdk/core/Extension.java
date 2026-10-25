package ru.neverlauncher.sdk.core;

/** Extension lifecycle is invoked on dedicated managed worker threads, not HTTP request threads. */
public interface Extension {
    void start(ExtensionContext context) throws Exception;
    void stop(ExtensionContext context) throws Exception;
}
