package ru.launcher.sdk.core;

/** Lifecycle contract for a provider running inside one authenticated Java extension JVM.
 * Implementations are ordinary Java services; privileged host operations must use RuntimeServices.
 */
public interface JavaProvider {
    void start(ProviderContext context) throws Exception;
    void stop(ProviderContext context) throws Exception;
}
