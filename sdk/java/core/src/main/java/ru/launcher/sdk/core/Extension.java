package ru.launcher.sdk.core;

/** Жизненный цикл расширения вызывается в выделенных управляемых рабочих потоках, а не в потоках HTTP-запросов. */
public interface Extension {
    void start(ExtensionContext context) throws Exception;
    void stop(ExtensionContext context) throws Exception;
}
