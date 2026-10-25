package ru.neverlauncher.sdk.core;

import java.util.Objects;

/** Immutable startup identity and cooperative termination context. */
public record ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline) {
    public ExtensionContext {Objects.requireNonNull(manifest);Objects.requireNonNull(cancellation);Objects.requireNonNull(deadline);}
    public void checkActive() throws java.util.concurrent.TimeoutException {cancellation.throwIfCancelled();deadline.check();}
}
