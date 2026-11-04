package ru.launcher.trusted;

import java.lang.instrument.Instrumentation;

/** Работает внутри JVM Minecraft с неограниченными привилегиями. НЕ изолирован в песочнице. */
public interface MinecraftHook {
    default void onAgentReady(Instrumentation instrumentation) throws Exception { }
    default void beforeMinecraftMain(String mainClass, String[] args, ClassLoader contextLoader) throws Exception { }
    /** Байткод до определения класса; вернуть null, чтобы оставить байты без изменений. */
    default byte[] transformMinecraftClass(String binaryClassName, ClassLoader definingLoader, byte[] classBytes) throws Exception { return null; }
    /** Вызывается при завершении Minecraft main(String[]), включая аварийный выход. */
    default void afterMinecraftMain(String mainClass, Throwable failure) throws Exception { }
}
