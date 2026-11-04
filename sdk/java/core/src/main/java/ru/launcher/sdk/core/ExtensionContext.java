package ru.launcher.sdk.core;

import java.util.Objects;

/** Неизменяемая идентичность запуска, сервисы Runtime, реестр SPI и контекст кооперативного завершения. */
public record ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline,
        RuntimeServices runtime, ProviderRegistry providers) {
    public ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline) {
        this(manifest, cancellation, deadline, null, null);
    }
    /** Старый конструктор с четырьмя аргументами доступен для расширений до 0.48.3. */
    public ExtensionContext(ExtensionManifest manifest, Cancellation cancellation, Deadline deadline, RuntimeServices runtime) {
        this(manifest, cancellation, deadline, runtime, null);
    }
    public ExtensionContext {
        Objects.requireNonNull(manifest); Objects.requireNonNull(cancellation); Objects.requireNonNull(deadline);
    }
    public void checkActive() throws java.util.concurrent.TimeoutException {cancellation.throwIfCancelled();deadline.check();}
}
