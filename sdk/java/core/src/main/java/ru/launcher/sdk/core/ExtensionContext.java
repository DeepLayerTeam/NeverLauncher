package ru.launcher.sdk.core;

import java.util.Objects;

/** Immutable startup identity, runtime services, SPI registry and cooperative termination context. */
public record ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline,
        RuntimeServices runtime, ProviderRegistry providers) {
    public ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline) {
        this(manifest, cancellation, deadline, null, null);
    }
    /** Old four-argument constructor remains available for pre-0.48.3 extensions. */
    public ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline, RuntimeServices runtime) {
        this(manifest, cancellation, deadline, runtime, null);
    }
    public ExtensionContext {
        Objects.requireNonNull(manifest); Objects.requireNonNull(cancellation); Objects.requireNonNull(deadline);
    }
    public void checkActive() throws java.util.concurrent.TimeoutException {cancellation.throwIfCancelled();deadline.check();}
}
