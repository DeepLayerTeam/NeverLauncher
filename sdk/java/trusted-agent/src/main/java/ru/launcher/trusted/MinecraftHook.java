package ru.launcher.trusted;

import java.lang.instrument.Instrumentation;

/** Runs within Minecraft JVM with unrestricted privileges. NOT sandboxed. */
public interface MinecraftHook {
    default void onAgentReady(Instrumentation instrumentation) throws Exception { }
    default void beforeMinecraftMain(String mainClass, String[] args, ClassLoader contextLoader) throws Exception { }
    /** Bytecode before definition; return null to keep unchanged bytes. */
    default byte[] transformMinecraftClass(String binaryClassName, ClassLoader definingLoader, byte[] classBytes) throws Exception { return null; }
    /** Called when Minecraft main(String[]) exits, including exceptional exit. */
    default void afterMinecraftMain(String mainClass, Throwable failure) throws Exception { }
}
