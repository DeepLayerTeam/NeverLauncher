package ru.launcher.sdk.core;

import java.util.Objects;

/** Immutable startup identity and cooperative termination context. */
public record ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline, RuntimeServices runtime) {
    public ExtensionContext(ExtensionManifest manifest,Cancellation cancellation,Deadline deadline){this(manifest,cancellation,deadline,null);}
    public ExtensionContext {Objects.requireNonNull(manifest);Objects.requireNonNull(cancellation);Objects.requireNonNull(deadline);}
    public void checkActive() throws java.util.concurrent.TimeoutException {cancellation.throwIfCancelled();deadline.check();}
}
