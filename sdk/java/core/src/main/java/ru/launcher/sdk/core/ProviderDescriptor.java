package ru.launcher.sdk.core;

import java.util.Objects;
import java.util.function.Supplier;

/** Implementation metadata checked before any provider constructor is invoked. */
public record ProviderDescriptor<T extends JavaProvider>(
        ProviderService<T> service, String id, SemVer version,
        String supportedSpi, String supportedExtensionApi, Supplier<? extends T> factory) {
    public ProviderDescriptor {
        Objects.requireNonNull(service, "service");
        if (id == null || !id.matches("[a-z][a-z0-9._-]{1,79}"))
            throw new IllegalArgumentException("invalid provider id");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(factory, "factory");
        // Разбирайте сейчас, до того как библиотека получит возможность выполнить
        // конструктор.
        SemVer.parse("0.0.0").matches(supportedSpi);
        SemVer.parse("0.0.0").matches(supportedExtensionApi);
    }
}
