package ru.launcher.sdk.core;

import java.util.Objects;

/** Authenticated extension scope and bounded lifecycle context for a Java SPI provider. */
public record ProviderContext(ExtensionManifest manifest, String serviceId, String providerId,
        Cancellation cancellation, Deadline deadline, RuntimeServices runtime) {
    public ProviderContext {
        Objects.requireNonNull(manifest); Objects.requireNonNull(serviceId);
        Objects.requireNonNull(providerId); Objects.requireNonNull(cancellation);
        Objects.requireNonNull(deadline);
    }
    public void checkActive() throws java.util.concurrent.TimeoutException {
        cancellation.throwIfCancelled(); deadline.check();
    }
}
